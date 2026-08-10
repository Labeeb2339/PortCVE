using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml;

namespace PortCVE.Remote.Imports;

internal static class NessusXmlImporter
{
    private const long MaximumXmlCharacters = 256L * 1024 * 1024;
    private const int MaximumDepth = 32;
    private const int MaximumElements = 2000000;
    private const int MaximumAttributesPerElement = 64;
    private const int MaximumReports = 16;
    private const int MaximumHosts = 4096;
    private const int MaximumItems = 200000;
    private const int MaximumItemsPerHost = 50000;
    private const int MaximumCvesPerItem = 64;
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
        var diagnosticCodes = new HashSet<string>(StringComparer.Ordinal);
        var endpoints = new List<ImportedEndpoint>();
        var findings = new List<ImportedFinding>();
        var privateHostAliases = new List<ImportedHostAlias>();
        var retentionBudget = new ImportRetentionBudget(MaximumRetainedCharacters);
        var sawRoot = false;
        var sawReport = false;
        var sourceVersion = (string?)null;
        var rootDepth = -1;
        var reportDepth = -1;
        var hostDepth = -1;
        var hostPropertiesDepth = -1;
        var itemDepth = -1;
        var elementCount = 0;
        var reportCount = 0;
        var hostCount = 0;
        var itemCount = 0;
        HostAccumulator? host = null;
        ItemAccumulator? item = null;

        using var reader = XmlReader.Create(stream, settings);
        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (reader.Depth > MaximumDepth)
            {
                throw new InvalidDataException($"Nessus XML exceeds the maximum element depth of {MaximumDepth}.");
            }

            if (reader.NodeType == XmlNodeType.Element)
            {
                elementCount++;
                if (elementCount > MaximumElements)
                {
                    throw new InvalidDataException($"Nessus XML exceeds the {MaximumElements} element import limit.");
                }

                if (reader.AttributeCount > MaximumAttributesPerElement)
                {
                    throw new InvalidDataException(
                        $"Nessus XML element exceeds the {MaximumAttributesPerElement} attribute limit.");
                }

                var elementName = reader.LocalName;
                var elementDepth = reader.Depth;
                var isEmpty = reader.IsEmptyElement;
                var isUnqualified = reader.NamespaceURI.Length == 0;
                if (!sawRoot)
                {
                    if (!isUnqualified || elementDepth != 0 || elementName != "NessusClientData_v2")
                    {
                        throw new InvalidDataException(
                            "Nessus XML must have a NessusClientData_v2 document element.");
                    }

                    sawRoot = true;
                    rootDepth = elementDepth;
                    sourceVersion = ImportText.SanitizeIdentifier(
                        ReadAttribute(reader, "version", 64, cancellationToken),
                        64);
                    continue;
                }

                var handled = false;
                if (isUnqualified
                    && elementName == "Report"
                    && elementDepth == rootDepth + 1
                    && reportDepth < 0)
                {
                    reportCount++;
                    if (reportCount > MaximumReports)
                    {
                        throw new InvalidDataException(
                            $"Nessus XML exceeds the {MaximumReports} report import limit.");
                    }

                    sawReport = true;
                    reportDepth = isEmpty ? -1 : elementDepth;
                    handled = true;
                }
                else if (isUnqualified
                    && reportDepth >= 0
                    && elementName == "ReportHost"
                    && elementDepth == reportDepth + 1
                    && host is null)
                {
                    hostCount++;
                    if (hostCount > MaximumHosts)
                    {
                        throw new InvalidDataException(
                            $"Nessus XML exceeds the {MaximumHosts} host import limit.");
                    }

                    var rawName = ReadAttribute(reader, "name", 2048, cancellationToken);
                    var nameTarget = ImportText.SanitizeTarget(rawName);
                    var nameLabel = ImportText.SanitizePublicLabel(rawName, 253);
                    host = new(nameTarget, NormalizeHostname(nameLabel));
                    hostDepth = elementDepth;
                    hostPropertiesDepth = -1;
                    handled = true;
                }
                else if (isUnqualified
                    && host is not null
                    && elementName == "HostProperties"
                    && elementDepth == hostDepth + 1
                    && hostPropertiesDepth < 0)
                {
                    hostPropertiesDepth = isEmpty ? -1 : elementDepth;
                    handled = true;
                }
                else if (isUnqualified
                    && host is not null
                    && hostPropertiesDepth >= 0
                    && elementName == "tag"
                    && elementDepth == hostPropertiesDepth + 1)
                {
                    ReadHostProperty(
                        reader,
                        host,
                        diagnostics,
                        diagnosticCodes,
                        retentionBudget,
                        cancellationToken);
                    handled = true;
                    continue;
                }
                else if (isUnqualified
                    && host is not null
                    && item is null
                    && elementName == "ReportItem"
                    && elementDepth == hostDepth + 1)
                {
                    itemCount++;
                    if (itemCount > MaximumItems)
                    {
                        throw new InvalidDataException(
                            $"Nessus XML exceeds the {MaximumItems} report-item import limit.");
                    }

                    if (host.Items.Count >= MaximumItemsPerHost)
                    {
                        throw new InvalidDataException(
                            $"A Nessus host exceeds the {MaximumItemsPerHost} report-item import limit.");
                    }

                    item = ReadItem(reader, cancellationToken);
                    itemDepth = elementDepth;
                    handled = true;
                }
                else if (isUnqualified
                    && item is not null
                    && elementName == "cve"
                    && elementDepth == itemDepth + 1)
                {
                    ReadCve(
                        reader,
                        item,
                        diagnostics,
                        diagnosticCodes,
                        retentionBudget,
                        cancellationToken);
                    handled = true;
                    continue;
                }

                if (!handled && IsStructuralEvidenceElement(elementName))
                {
                    AddDiagnostic(
                        diagnostics,
                        diagnosticCodes,
                        retentionBudget,
                        "nessus_structure_ignored",
                        "Nessus evidence outside the canonical Report/ReportHost/ReportItem paths was ignored.");
                }

                if (isEmpty)
                {
                    if (item is not null && elementDepth == itemDepth && elementName == "ReportItem")
                    {
                        FinalizeItem(
                            host!,
                            item,
                            diagnostics,
                            diagnosticCodes,
                            retentionBudget);
                        item = null;
                        itemDepth = -1;
                    }

                    if (host is not null && elementDepth == hostDepth && elementName == "ReportHost")
                    {
                        FinalizeHost(
                            host,
                            endpoints,
                            findings,
                            privateHostAliases,
                            diagnostics,
                            diagnosticCodes,
                            retentionBudget);
                        host = null;
                        hostDepth = -1;
                        hostPropertiesDepth = -1;
                    }
                }
            }
            else if (reader.NodeType == XmlNodeType.EndElement && reader.NamespaceURI.Length == 0)
            {
                if (item is not null && reader.Depth == itemDepth && reader.LocalName == "ReportItem")
                {
                    FinalizeItem(
                        host!,
                        item,
                        diagnostics,
                        diagnosticCodes,
                        retentionBudget);
                    item = null;
                    itemDepth = -1;
                }

                if (hostPropertiesDepth >= 0
                    && reader.Depth == hostPropertiesDepth
                    && reader.LocalName == "HostProperties")
                {
                    hostPropertiesDepth = -1;
                }

                if (host is not null && reader.Depth == hostDepth && reader.LocalName == "ReportHost")
                {
                    FinalizeHost(
                        host,
                        endpoints,
                        findings,
                        privateHostAliases,
                        diagnostics,
                        diagnosticCodes,
                        retentionBudget);
                    host = null;
                    hostDepth = -1;
                    hostPropertiesDepth = -1;
                }

                if (reportDepth >= 0 && reader.Depth == reportDepth && reader.LocalName == "Report")
                {
                    reportDepth = -1;
                }
            }
        }

        if (!sawRoot)
        {
            throw new InvalidDataException("Nessus XML must have a NessusClientData_v2 document element.");
        }

        if (!sawReport)
        {
            AddDiagnostic(
                diagnostics,
                diagnosticCodes,
                retentionBudget,
                "nessus_report_missing",
                "Nessus XML did not contain a canonical Report element; imported evidence is incomplete.");
        }

        return new(
            "nessus_xml",
            sourceVersion,
            sawReport && diagnostics.Count == 0,
            endpoints.OrderBy(static endpoint => endpoint.Target, StringComparer.Ordinal)
                .ThenBy(static endpoint => endpoint.Protocol, StringComparer.Ordinal)
                .ThenBy(static endpoint => endpoint.Port)
                .ToArray(),
            findings.OrderBy(static finding => finding.Target, StringComparer.Ordinal)
                .ThenBy(static finding => finding.Port)
                .ThenBy(static finding => finding.FindingId, StringComparer.Ordinal)
                .ToArray(),
            diagnostics)
        {
            PrivateHostAliases = privateHostAliases,
        };
    }

    private static ItemAccumulator ReadItem(XmlReader reader, CancellationToken cancellationToken)
    {
        var rawTitle = ReadAttribute(reader, "pluginName", 512, cancellationToken);
        return new(
            ReadAttribute(reader, "pluginID", 32, cancellationToken),
            ImportText.SanitizePublicLabel(rawTitle, 512),
            ReadAttribute(reader, "port", 5, cancellationToken),
            ImportText.SanitizeIdentifier(
                ReadAttribute(reader, "protocol", 16, cancellationToken),
                16)?.ToLowerInvariant(),
            ReadAttribute(reader, "severity", 32, cancellationToken),
            ImportText.SanitizePublicLabel(
                ReadAttribute(reader, "svc_name", 128, cancellationToken),
                128));
    }

    private static void ReadHostProperty(
        XmlReader reader,
        HostAccumulator host,
        ICollection<PentestImportDiagnostic> diagnostics,
        ISet<string> diagnosticCodes,
        ImportRetentionBudget retentionBudget,
        CancellationToken cancellationToken)
    {
        var name = ReadAttribute(reader, "name", 64, cancellationToken);
        if (name is null)
        {
            return;
        }

        if (name.Equals("host-ip", StringComparison.OrdinalIgnoreCase))
        {
            var value = ReadElementText(reader, 64, "host-ip", cancellationToken);
            if (value is not null && IPAddress.TryParse(value, out var address))
            {
                host.IpTarget = address.AddressFamily == AddressFamily.InterNetworkV6
                    ? $"[{address}]"
                    : address.ToString();
            }
            else
            {
                AddDiagnostic(
                    diagnostics,
                    diagnosticCodes,
                    retentionBudget,
                    "nessus_host_ip_invalid",
                    "A Nessus host-ip property was invalid and was not used for target attribution.");
            }
        }
        else if (name.Equals("host-fqdn", StringComparison.OrdinalIgnoreCase)
            || name.Equals("hostname", StringComparison.OrdinalIgnoreCase))
        {
            var value = ReadElementText(reader, 253, name, cancellationToken);
            var hostname = NormalizeHostname(ImportText.SanitizePublicLabel(value, 253));
            if (hostname is not null)
            {
                host.Hostname = hostname;
            }
            else if (value is not null)
            {
                AddDiagnostic(
                    diagnostics,
                    diagnosticCodes,
                    retentionBudget,
                    "nessus_hostname_invalid",
                    "A Nessus hostname property was invalid and was omitted.");
            }
        }
    }

    private static void ReadCve(
        XmlReader reader,
        ItemAccumulator item,
        ICollection<PentestImportDiagnostic> diagnostics,
        ISet<string> diagnosticCodes,
        ImportRetentionBudget retentionBudget,
        CancellationToken cancellationToken)
    {
        if (item.Cves.Count >= MaximumCvesPerItem)
        {
            AddDiagnostic(
                diagnostics,
                diagnosticCodes,
                retentionBudget,
                "nessus_cve_limit_exceeded",
                $"A Nessus report item exceeded the {MaximumCvesPerItem} CVE retention limit.");
            return;
        }

        var raw = ReadElementText(reader, 64, "cve", cancellationToken);
        var cve = NormalizeCve(raw);
        if (cve is null)
        {
            AddDiagnostic(
                diagnostics,
                diagnosticCodes,
                retentionBudget,
                "nessus_cve_invalid",
                "A malformed Nessus CVE identifier was omitted.");
            return;
        }

        item.Cves.Add(cve);
    }

    private static void FinalizeItem(
        HostAccumulator host,
        ItemAccumulator item,
        ICollection<PentestImportDiagnostic> diagnostics,
        ISet<string> diagnosticCodes,
        ImportRetentionBudget retentionBudget)
    {
        var pluginId = NormalizePluginId(item.PluginId);
        if (pluginId is null)
        {
            AddDiagnostic(
                diagnostics,
                diagnosticCodes,
                retentionBudget,
                "nessus_item_invalid",
                "A Nessus report item without a valid numeric plugin ID was ignored.");
            return;
        }

        if (!int.TryParse(item.PortText, NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            || port is < 0 or > 65535)
        {
            AddDiagnostic(
                diagnostics,
                diagnosticCodes,
                retentionBudget,
                "nessus_item_invalid",
                "A Nessus report item with an invalid port was ignored.");
            return;
        }

        string? protocol = null;
        int? normalizedPort = null;
        if (port > 0)
        {
            if (item.Protocol is not "tcp" and not "udp")
            {
                AddDiagnostic(
                    diagnostics,
                    diagnosticCodes,
                    retentionBudget,
                    "nessus_item_invalid",
                    "A Nessus report item with an unsupported endpoint protocol was ignored.");
                return;
            }

            protocol = item.Protocol;
            normalizedPort = port;
        }

        var severity = NormalizeSeverity(item.SeverityText);
        if (severity == "unknown")
        {
            AddDiagnostic(
                diagnostics,
                diagnosticCodes,
                retentionBudget,
                "nessus_severity_invalid",
                "A Nessus report item had an invalid severity and was retained as unknown.");
        }

        if (item.Title is null)
        {
            AddDiagnostic(
                diagnostics,
                diagnosticCodes,
                retentionBudget,
                "nessus_title_omitted",
                "A Nessus report-item title was missing or could not be retained safely and was replaced by its plugin ID.");
        }

        var title = item.Title ?? $"Nessus plugin {pluginId}";
        var pending = new PendingItem(
            pluginId,
            title,
            severity,
            protocol,
            normalizedPort,
            item.ServiceName,
            item.Cves.ToArray());
        retentionBudget.Reserve(PendingItemCharacters(pending));
        host.Items.Add(pending);
    }

    private static void FinalizeHost(
        HostAccumulator host,
        ICollection<ImportedEndpoint> endpoints,
        ICollection<ImportedFinding> findings,
        ICollection<ImportedHostAlias> privateHostAliases,
        ICollection<PentestImportDiagnostic> diagnostics,
        ISet<string> diagnosticCodes,
        ImportRetentionBudget retentionBudget)
    {
        var target = host.IpTarget ?? host.NameTarget;
        if (target is null)
        {
            AddDiagnostic(
                diagnostics,
                diagnosticCodes,
                retentionBudget,
                "nessus_host_without_target",
                "A Nessus host record had no safe IP address or hostname; its report items were ignored.");
            return;
        }

        privateHostAliases.Add(new(target, host.Hostname));

        var endpointServices = new Dictionary<(string Protocol, int Port), string?>();
        foreach (var pending in host.Items)
        {
            if (pending.Port is not null && pending.Protocol is not null)
            {
                var key = (pending.Protocol, pending.Port.Value);
                if (!endpointServices.TryGetValue(key, out var existingService)
                    || existingService is null && pending.ServiceName is not null)
                {
                    endpointServices[key] = pending.ServiceName;
                }
            }

            var sourceRecord = string.Join(
                '|',
                target,
                pending.Protocol ?? string.Empty,
                pending.Port?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                pending.PluginId,
                pending.Title,
                pending.Severity,
                string.Join(',', pending.Cves));
            var finding = new ImportedFinding(
                "nessus_xml",
                pending.PluginId,
                pending.Title,
                pending.Severity,
                target,
                pending.Port,
                pending.Protocol,
                ImportedClaimStatus.ImportedMatch,
                ImportedEvidenceStrength.Unresolved,
                pending.Cves,
                [],
                ImportText.Sha256(sourceRecord),
                pending.PluginId,
                null);
            retentionBudget.Reserve(FindingCharacters(finding));
            findings.Add(finding);
        }

        foreach (var endpoint in endpointServices)
        {
            var service = endpoint.Value is null
                ? null
                : new ImportedServiceIdentity(
                    endpoint.Value,
                    null,
                    null,
                    null,
                    [],
                    ImportedEvidenceStrength.Weak,
                    "nessus_report_item");
            retentionBudget.Reserve(ImportRetentionBudget.Characters(
                target,
                host.Hostname,
                endpoint.Key.Protocol,
                "reported",
                endpoint.Value,
                service?.EvidenceSource));
            endpoints.Add(new(
                target,
                host.Hostname,
                endpoint.Key.Protocol,
                endpoint.Key.Port,
                "reported",
                null,
                service));
        }
    }

    private static string NormalizeSeverity(string? value) => value switch
    {
        "0" => "info",
        "1" => "low",
        "2" => "medium",
        "3" => "high",
        "4" => "critical",
        _ => "unknown",
    };

    private static string? NormalizePluginId(string? value) =>
        value is not null && value.Length <= 16 && ContainsOnlyAsciiDigits(value)
            ? value.TrimStart('0') is { Length: > 0 } normalized ? normalized : "0"
            : null;

    private static string? NormalizeCve(string? value)
    {
        var candidate = ImportText.SanitizeIdentifier(value, 64)?.ToUpperInvariant();
        if (candidate is null
            || !candidate.StartsWith("CVE-", StringComparison.Ordinal)
            || candidate.Length < 13
            || candidate[8] != '-'
            || !ContainsOnlyAsciiDigits(candidate.AsSpan(4, 4))
            || !ContainsOnlyAsciiDigits(candidate.AsSpan(9)))
        {
            return null;
        }

        return candidate;
    }

    private static string? NormalizeHostname(string? value)
    {
        if (value is null
            || value.Length > 253
            || IPAddress.TryParse(value.Trim('[', ']'), out _)
            || value.Contains(':', StringComparison.Ordinal)
            || value.Contains('/', StringComparison.Ordinal)
            || value.Contains('\\', StringComparison.Ordinal)
            || value.Contains('@', StringComparison.Ordinal))
        {
            return null;
        }

        return value;
    }

    private static bool ContainsOnlyAsciiDigits(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsStructuralEvidenceElement(string name) =>
        name is "Report" or "ReportHost" or "HostProperties" or "tag" or "ReportItem" or "cve";

    private static long PendingItemCharacters(PendingItem item) =>
        ImportRetentionBudget.Characters(
            item.PluginId,
            item.Title,
            item.Severity,
            item.Protocol,
            item.ServiceName)
        + ImportRetentionBudget.Characters(item.Cves);

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
        ISet<string> diagnosticCodes,
        ImportRetentionBudget retentionBudget,
        string code,
        string message)
    {
        if (!diagnosticCodes.Add(code))
        {
            return;
        }

        retentionBudget.Reserve(ImportRetentionBudget.Characters(code, message));
        diagnostics.Add(new(code, message));
    }

    private static string? ReadAttribute(
        XmlReader reader,
        string name,
        int maximumCharacters,
        CancellationToken cancellationToken)
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
                cancellationToken.ThrowIfCancellationRequested();
                var count = reader.ReadValueChunk(buffer, 0, buffer.Length);
                if (count == 0)
                {
                    break;
                }

                if (builder.Length + count > maximumCharacters)
                {
                    throw new InvalidDataException(
                        $"Nessus XML attribute '{name}' exceeds the {maximumCharacters} character limit.");
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
        string fieldName,
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
                throw new InvalidDataException($"Nessus XML exceeds the maximum element depth of {MaximumDepth}.");
            }

            if (reader.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.SignificantWhitespace)
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var count = reader.ReadValueChunk(buffer, 0, buffer.Length);
                    if (count == 0)
                    {
                        break;
                    }

                    if (builder.Length + count > maximumCharacters)
                    {
                        throw new InvalidDataException(
                            $"Nessus XML {fieldName} text exceeds the {maximumCharacters} character limit.");
                    }

                    builder.Append(buffer, 0, count);
                }
            }
            else if (reader.NodeType == XmlNodeType.Element)
            {
                throw new InvalidDataException($"Nessus XML {fieldName} values cannot contain nested elements.");
            }
            else if (reader.NodeType == XmlNodeType.EndElement && reader.Depth == elementDepth)
            {
                return ImportText.Sanitize(builder.ToString(), maximumCharacters);
            }
        }

        throw new InvalidDataException($"Nessus XML ended inside a {fieldName} value.");
    }

    private sealed class HostAccumulator(string? nameTarget, string? hostname)
    {
        public string? NameTarget { get; } = nameTarget;

        public string? IpTarget { get; set; }

        public string? Hostname { get; set; } = hostname;

        public List<PendingItem> Items { get; } = [];
    }

    private sealed class ItemAccumulator(
        string? pluginId,
        string? title,
        string? portText,
        string? protocol,
        string? severityText,
        string? serviceName)
    {
        public string? PluginId { get; } = pluginId;

        public string? Title { get; } = title;

        public string? PortText { get; } = portText;

        public string? Protocol { get; } = protocol;

        public string? SeverityText { get; } = severityText;

        public string? ServiceName { get; } = serviceName;

        public SortedSet<string> Cves { get; } = new(StringComparer.Ordinal);
    }

    private sealed record PendingItem(
        string PluginId,
        string Title,
        string Severity,
        string? Protocol,
        int? Port,
        string? ServiceName,
        IReadOnlyList<string> Cves);
}
