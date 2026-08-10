using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml;

namespace PortCVE.Remote.Imports;

internal static class NmapXmlImporter
{
    private const long MaximumXmlCharacters = 64L * 1024 * 1024;
    private const int MaximumDepth = 32;
    private const int MaximumElements = 1000000;
    private const int MaximumAttributesPerElement = 64;
    private const int MaximumHosts = 4096;
    private const int MaximumEndpoints = 200000;
    private const int MaximumScriptObservations = 50000;
    private const long MaximumRetainedCharacters = 16L * 1024 * 1024;

    public static PentestImportReport Import(Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaximumXmlCharacters,
            MaxCharactersFromEntities = 0,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            IgnoreWhitespace = true,
            CloseInput = false,
        };

        var diagnostics = new List<PentestImportDiagnostic>();
        var endpoints = new List<ImportedEndpoint>();
        var findings = new List<ImportedFinding>();
        var retentionBudget = new ImportRetentionBudget(MaximumRetainedCharacters);
        var sawRoot = false;
        var rootDepth = -1;
        var sourceVersion = (string?)null;
        var finishState = (string?)null;
        var elementCount = 0;
        var hostCount = 0;
        var endpointCount = 0;
        var scriptCount = 0;
        HostAccumulator? host = null;
        PortAccumulator? port = null;
        var hostDepth = -1;
        var hostnamesDepth = -1;
        var portsDepth = -1;
        var portDepth = -1;
        var serviceDepth = -1;
        var runstatsDepth = -1;

        using var reader = XmlReader.Create(stream, settings);
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (reader.Depth > MaximumDepth)
            {
                throw new InvalidDataException($"Nmap XML exceeds the maximum element depth of {MaximumDepth}.");
            }

            if (reader.NodeType == XmlNodeType.Element)
            {
                elementCount++;
                if (elementCount > MaximumElements)
                {
                    throw new InvalidDataException($"Nmap XML exceeds the {MaximumElements} element import limit.");
                }

                if (reader.AttributeCount > MaximumAttributesPerElement)
                {
                    throw new InvalidDataException(
                        $"Nmap XML element exceeds the {MaximumAttributesPerElement} attribute limit.");
                }

                var elementName = reader.LocalName;
                var elementDepth = reader.Depth;
                var isEmpty = reader.IsEmptyElement;
                if (!sawRoot)
                {
                    if (elementDepth != 0 || elementName != "nmaprun" || reader.NamespaceURI.Length != 0)
                    {
                        throw new InvalidDataException("Nmap XML must have an nmaprun document element.");
                    }

                    sawRoot = true;
                    rootDepth = elementDepth;
                    sourceVersion = ImportText.SanitizeIdentifier(ReadAttribute(reader, "version", 64), 64);
                    continue;
                }

                var isUnqualified = reader.NamespaceURI.Length == 0;
                if (isUnqualified && elementName == "runstats" && elementDepth == rootDepth + 1)
                {
                    runstatsDepth = isEmpty ? -1 : elementDepth;
                }
                else if (isUnqualified && elementName == "host" && elementDepth == rootDepth + 1)
                {
                    if (host is not null)
                    {
                        throw new InvalidDataException("Nmap XML contains nested host records.");
                    }

                    hostCount++;
                    if (hostCount > MaximumHosts)
                    {
                        throw new InvalidDataException($"Nmap XML exceeds the {MaximumHosts} host import limit.");
                    }

                    host = new();
                    hostDepth = elementDepth;
                    hostnamesDepth = -1;
                    portsDepth = -1;
                }
                else if (isUnqualified && host is not null && elementName == "address" && elementDepth == hostDepth + 1)
                {
                    ReadAddress(reader, host);
                }
                else if (isUnqualified
                    && host is not null
                    && elementName == "hostnames"
                    && elementDepth == hostDepth + 1)
                {
                    hostnamesDepth = isEmpty ? -1 : elementDepth;
                }
                else if (isUnqualified
                    && host is not null
                    && hostnamesDepth >= 0
                    && elementName == "hostname"
                    && elementDepth == hostnamesDepth + 1
                    && host.Hostname is null)
                {
                    host.Hostname = ImportText.SanitizePublicLabel(ReadAttribute(reader, "name", 253), 253);
                }
                else if (isUnqualified
                    && host is not null
                    && elementName == "ports"
                    && elementDepth == hostDepth + 1)
                {
                    portsDepth = isEmpty ? -1 : elementDepth;
                }
                else if (isUnqualified
                    && host is not null
                    && portsDepth >= 0
                    && port is null
                    && elementName == "port"
                    && elementDepth == portsDepth + 1)
                {
                    endpointCount++;
                    if (endpointCount > MaximumEndpoints)
                    {
                        throw new InvalidDataException($"Nmap XML exceeds the {MaximumEndpoints} endpoint import limit.");
                    }

                    port = new(
                        ReadAttribute(reader, "protocol", 8)?.ToLowerInvariant(),
                        ReadAttribute(reader, "portid", 5));
                    portDepth = elementDepth;
                }
                else if (isUnqualified && port is not null && elementName == "state" && elementDepth == portDepth + 1)
                {
                    port.State = NormalizePortState(ReadAttribute(reader, "state", 32));
                    port.StateReason = ImportText.SanitizeIdentifier(ReadAttribute(reader, "reason", 128), 128);
                }
                else if (isUnqualified && port is not null && elementName == "service" && elementDepth == portDepth + 1)
                {
                    port.Service = ReadService(reader);
                    serviceDepth = isEmpty ? -1 : elementDepth;
                }
                else if (port is not null
                    && port.Service is not null
                    && serviceDepth >= 0
                    && isUnqualified
                    && elementName == "cpe"
                    && elementDepth == serviceDepth + 1)
                {
                    var cpe = ImportText.SanitizePublicLabel(
                        ReadElementText(reader, 512, cancellationToken),
                        512);
                    if (cpe is not null
                        && port.Service.Cpes.Count < 8
                        && (cpe.StartsWith("cpe:/", StringComparison.Ordinal)
                            || cpe.StartsWith("cpe:2.3:", StringComparison.Ordinal)))
                    {
                        port.Service.Cpes.Add(cpe);
                    }

                    continue;
                }
                else if (isUnqualified && port is not null && elementName == "script" && elementDepth == portDepth + 1)
                {
                    var id = ImportText.SanitizeIdentifier(ReadAttribute(reader, "id", 256), 256);
                    if (id is not null)
                    {
                        scriptCount++;
                        if (scriptCount > MaximumScriptObservations)
                        {
                            throw new InvalidDataException(
                                $"Nmap XML exceeds the {MaximumScriptObservations} script-observation import limit.");
                        }

                        port.ScriptIds.Add(id);
                    }
                }
                else if (isUnqualified
                    && finishState is null
                    && runstatsDepth >= 0
                    && elementName == "finished"
                    && elementDepth == runstatsDepth + 1)
                {
                    finishState = NormalizeFinishState(ReadAttribute(reader, "exit", 16));
                }

                if (isEmpty)
                {
                    if (port is not null && elementDepth == portDepth && elementName == "port")
                    {
                        FinalizePort(host!, port, diagnostics, retentionBudget);
                        port = null;
                        portDepth = -1;
                        serviceDepth = -1;
                    }

                    if (host is not null && elementDepth == hostDepth && elementName == "host")
                    {
                        FinalizeHost(host, endpoints, findings, diagnostics, retentionBudget);
                        host = null;
                        hostDepth = -1;
                        hostnamesDepth = -1;
                        portsDepth = -1;
                    }
                }
            }
            else if (reader.NodeType == XmlNodeType.EndElement)
            {
                if (serviceDepth >= 0 && reader.Depth == serviceDepth && reader.LocalName == "service")
                {
                    serviceDepth = -1;
                }

                if (runstatsDepth >= 0 && reader.Depth == runstatsDepth && reader.LocalName == "runstats")
                {
                    runstatsDepth = -1;
                }

                if (hostnamesDepth >= 0
                    && reader.Depth == hostnamesDepth
                    && reader.LocalName == "hostnames"
                    && reader.NamespaceURI.Length == 0)
                {
                    hostnamesDepth = -1;
                }

                if (portsDepth >= 0
                    && reader.Depth == portsDepth
                    && reader.LocalName == "ports"
                    && reader.NamespaceURI.Length == 0)
                {
                    portsDepth = -1;
                }

                if (port is not null && reader.Depth == portDepth && reader.LocalName == "port")
                {
                    FinalizePort(host!, port, diagnostics, retentionBudget);
                    port = null;
                    portDepth = -1;
                    serviceDepth = -1;
                }

                if (host is not null && reader.Depth == hostDepth && reader.LocalName == "host")
                {
                    FinalizeHost(host, endpoints, findings, diagnostics, retentionBudget);
                    host = null;
                    hostDepth = -1;
                    hostnamesDepth = -1;
                    portsDepth = -1;
                }
            }
        }

        if (!sawRoot)
        {
            throw new InvalidDataException("Nmap XML must have an nmaprun document element.");
        }

        var finishedSuccessfully = string.Equals(
            finishState,
            "success",
            StringComparison.OrdinalIgnoreCase);
        if (!finishedSuccessfully)
        {
            AddDiagnostic(
                diagnostics,
                retentionBudget,
                "nmap_scan_incomplete",
                "Nmap did not record a successful finished state; imported evidence may be incomplete.");
        }

        var evidenceWasDropped = diagnostics.Any(static diagnostic =>
            diagnostic.Code is "nmap_protocol_ignored" or "nmap_host_without_address");
        var complete = finishedSuccessfully && !evidenceWasDropped;

        return new(
            "nmap_xml",
            sourceVersion,
            complete,
            endpoints.OrderBy(static item => item.Target, StringComparer.Ordinal)
                .ThenBy(static item => item.Protocol, StringComparer.Ordinal)
                .ThenBy(static item => item.Port)
                .ToArray(),
            findings.OrderBy(static item => item.Target, StringComparer.Ordinal)
                .ThenBy(static item => item.Port)
                .ThenBy(static item => item.FindingId, StringComparer.Ordinal)
                .ToArray(),
            diagnostics);
    }

    private static void ReadAddress(XmlReader reader, HostAccumulator host)
    {
        var type = ReadAttribute(reader, "addrtype", 8);
        var rawAddress = ReadAttribute(reader, "addr", 64);
        if (rawAddress is null || !IPAddress.TryParse(rawAddress, out var parsed))
        {
            return;
        }

        if (type == "ipv4" && parsed.AddressFamily == AddressFamily.InterNetwork && host.Ipv4 is null)
        {
            host.Ipv4 = parsed.ToString();
        }
        else if (type == "ipv6" && parsed.AddressFamily == AddressFamily.InterNetworkV6 && host.Ipv6 is null)
        {
            host.Ipv6 = parsed.ToString();
        }
    }

    private static ServiceAccumulator ReadService(XmlReader reader)
    {
        var method = ReadAttribute(reader, "method", 16);
        _ = int.TryParse(
            ReadAttribute(reader, "conf", 3),
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out var confidence);
        var strength = method == "probed" && confidence >= 8 ? ImportedEvidenceStrength.Strong
            : method == "probed" && confidence >= 5 ? ImportedEvidenceStrength.Moderate
            : ImportedEvidenceStrength.Weak;
        return new(
            ImportText.SanitizePublicLabel(ReadAttribute(reader, "name", 128), 128),
            ImportText.SanitizePublicLabel(ReadAttribute(reader, "product", 256), 256),
            ImportText.SanitizePublicLabel(ReadAttribute(reader, "version", 128), 128),
            ImportText.SanitizePublicLabel(ReadAttribute(reader, "extrainfo", 256), 256),
            strength,
            method == "probed" ? "nmap_service_probe" : "nmap_port_table");
    }

    private static string NormalizePortState(string? value)
    {
        var candidate = value?.ToLowerInvariant();
        return candidate is "open"
            or "closed"
            or "filtered"
            or "unfiltered"
            or "open|filtered"
            or "closed|filtered"
            ? candidate
            : "unknown";
    }

    private static string? NormalizeFinishState(string? value)
    {
        var candidate = value?.ToLowerInvariant();
        return candidate is "success" or "error" ? candidate : null;
    }

    private static void FinalizePort(
        HostAccumulator host,
        PortAccumulator port,
        ICollection<PentestImportDiagnostic> diagnostics,
        ImportRetentionBudget retentionBudget)
    {
        if (port.Protocol is not "tcp" and not "udp")
        {
            AddDiagnostic(
                diagnostics,
                retentionBudget,
                "nmap_protocol_ignored",
                "An endpoint used an unsupported transport protocol.");
            return;
        }

        if (!int.TryParse(port.PortText, NumberStyles.None, CultureInfo.InvariantCulture, out var portNumber)
            || portNumber is < 1 or > 65535)
        {
            throw new InvalidDataException("Nmap XML contained an invalid port number.");
        }

        var service = port.Service is null
            ? null
            : new ImportedServiceIdentity(
                port.Service.Name,
                port.Service.Product,
                port.Service.Version,
                port.Service.ExtraInfo,
                port.Service.Cpes.Distinct(StringComparer.Ordinal).ToArray(),
                port.Service.EvidenceStrength,
                port.Service.EvidenceSource);
        var pending = new PendingEndpoint(
            port.Protocol,
            portNumber,
            port.State,
            port.StateReason,
            service,
            port.ScriptIds);
        retentionBudget.Reserve(PendingEndpointCharacters(pending));
        host.Endpoints.Add(pending);
    }

    private static void FinalizeHost(
        HostAccumulator host,
        ICollection<ImportedEndpoint> endpoints,
        ICollection<ImportedFinding> findings,
        ICollection<PentestImportDiagnostic> diagnostics,
        ImportRetentionBudget retentionBudget)
    {
        var address = host.Ipv4 ?? host.Ipv6;
        if (address is null)
        {
            AddDiagnostic(
                diagnostics,
                retentionBudget,
                "nmap_host_without_address",
                "An Nmap host record had no valid IPv4 or IPv6 address.");
            return;
        }

        foreach (var pending in host.Endpoints)
        {
            retentionBudget.Reserve(ImportRetentionBudget.Characters(address, host.Hostname));
            endpoints.Add(new(
                address,
                host.Hostname,
                pending.Protocol,
                pending.Port,
                pending.State,
                pending.StateReason,
                pending.Service));
            foreach (var id in pending.ScriptIds)
            {
                var sourceRecord = $"{address}|{pending.Protocol}|{pending.Port}|{id}";
                var finding = new ImportedFinding(
                    "nmap_nse",
                    id,
                    $"Imported Nmap NSE observation: {id}",
                    "unknown",
                    address,
                    pending.Port,
                    pending.Protocol,
                    ImportedClaimStatus.ImportedMatch,
                    ImportedEvidenceStrength.Unresolved,
                    [],
                    [],
                    ImportText.Sha256(sourceRecord),
                    id,
                    null);
                retentionBudget.Reserve(FindingCharacters(finding));
                findings.Add(finding);
            }
        }
    }

    private static long PendingEndpointCharacters(PendingEndpoint endpoint)
    {
        var characters = ImportRetentionBudget.Characters(
            endpoint.Protocol,
            endpoint.State,
            endpoint.StateReason)
            + ImportRetentionBudget.Characters(endpoint.ScriptIds);
        if (endpoint.Service is not null)
        {
            characters += ImportRetentionBudget.Characters(
                endpoint.Service.Name,
                endpoint.Service.Product,
                endpoint.Service.Version,
                endpoint.Service.ExtraInfo,
                endpoint.Service.EvidenceSource)
                + ImportRetentionBudget.Characters(endpoint.Service.Cpes);
        }

        return characters;
    }

    private static long FindingCharacters(ImportedFinding finding) =>
        ImportRetentionBudget.Characters(
            finding.Source,
            finding.FindingId,
            finding.Title,
            finding.Severity,
            finding.Target,
            finding.Protocol,
            finding.SourceRecordSha256,
            finding.Matcher,
            finding.Summary)
        + ImportRetentionBudget.Characters(finding.AdvisoryIds)
        + ImportRetentionBudget.Characters(finding.References);

    private static void AddDiagnostic(
        ICollection<PentestImportDiagnostic> diagnostics,
        ImportRetentionBudget retentionBudget,
        string code,
        string message)
    {
        retentionBudget.Reserve(ImportRetentionBudget.Characters(code, message));
        diagnostics.Add(new(code, message));
    }

    private static string? ReadAttribute(XmlReader reader, string name, int maximumCharacters)
    {
        if (!reader.MoveToAttribute(name))
        {
            return null;
        }

        try
        {
            var buffer = new char[Math.Min(maximumCharacters + 1, 512)];
            var builder = new StringBuilder(Math.Min(maximumCharacters, 256));
            while (true)
            {
                var count = reader.ReadValueChunk(buffer, 0, buffer.Length);
                if (count == 0)
                {
                    break;
                }

                if (builder.Length + count > maximumCharacters)
                {
                    throw new InvalidDataException(
                        $"Nmap XML attribute '{name}' exceeds the {maximumCharacters} character limit.");
                }

                builder.Append(buffer, 0, count);
            }

            return builder.Length == 0 ? null : builder.ToString();
        }
        finally
        {
            reader.MoveToElement();
        }
    }

    private static string? ReadElementText(
        XmlReader reader,
        int maximumCharacters,
        CancellationToken cancellationToken)
    {
        if (reader.IsEmptyElement)
        {
            return null;
        }

        var elementDepth = reader.Depth;
        var buffer = new char[Math.Min(maximumCharacters + 1, 512)];
        var builder = new StringBuilder(Math.Min(maximumCharacters, 256));
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (reader.Depth > MaximumDepth)
            {
                throw new InvalidDataException($"Nmap XML exceeds the maximum element depth of {MaximumDepth}.");
            }

            if (reader.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.SignificantWhitespace)
            {
                while (true)
                {
                    var count = reader.ReadValueChunk(buffer, 0, buffer.Length);
                    if (count == 0)
                    {
                        break;
                    }

                    if (builder.Length + count > maximumCharacters)
                    {
                        throw new InvalidDataException(
                            $"Nmap XML text value exceeds the {maximumCharacters} character limit.");
                    }

                    builder.Append(buffer, 0, count);
                }
            }
            else if (reader.NodeType == XmlNodeType.Element)
            {
                throw new InvalidDataException("Nmap XML CPE values cannot contain nested elements.");
            }
            else if (reader.NodeType == XmlNodeType.EndElement && reader.Depth == elementDepth)
            {
                return ImportText.Sanitize(builder.ToString(), maximumCharacters);
            }
        }

        throw new InvalidDataException("Nmap XML ended inside a CPE value.");
    }

    private sealed class HostAccumulator
    {
        public string? Ipv4 { get; set; }

        public string? Ipv6 { get; set; }

        public string? Hostname { get; set; }

        public List<PendingEndpoint> Endpoints { get; } = [];
    }

    private sealed class PortAccumulator(string? protocol, string? portText)
    {
        public string? Protocol { get; } = protocol;

        public string? PortText { get; } = portText;

        public string State { get; set; } = "unknown";

        public string? StateReason { get; set; }

        public ServiceAccumulator? Service { get; set; }

        public List<string> ScriptIds { get; } = [];
    }

    private sealed class ServiceAccumulator(
        string? name,
        string? product,
        string? version,
        string? extraInfo,
        ImportedEvidenceStrength evidenceStrength,
        string evidenceSource)
    {
        public string? Name { get; } = name;

        public string? Product { get; } = product;

        public string? Version { get; } = version;

        public string? ExtraInfo { get; } = extraInfo;

        public ImportedEvidenceStrength EvidenceStrength { get; } = evidenceStrength;

        public string EvidenceSource { get; } = evidenceSource;

        public List<string> Cpes { get; } = [];
    }

    private sealed record PendingEndpoint(
        string Protocol,
        int Port,
        string State,
        string? StateReason,
        ImportedServiceIdentity? Service,
        IReadOnlyList<string> ScriptIds);
}
