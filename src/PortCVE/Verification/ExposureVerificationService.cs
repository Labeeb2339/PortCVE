using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using PortCVE.Domain;
using PortCVE.Remote.Imports;
using PortCVE.Snapshots;

namespace PortCVE.Verification;

internal sealed class ExposureVerificationService
{
    private const int MaximumOutputEndpoints = 65_536;
    private const int MaximumSelectedFindings = 25_000;
    private const int MaximumFindingMemberships = 25_000;
    private const int MaximumPrivateRedactionAliases = 32;
    private const string ClaimBoundary =
        "Imported reachability is specific to its collection time and operator-labeled vantage. "
        + "The target-to-host association is asserted by the operator. A matching live listener identifies a plausible "
        + "local owner, but does not prove the imported connection reached that listener, that the path is currently "
        + "reachable, or that any reported vulnerability is applicable or exploitable.";

    internal ExposureVerificationReport Verify(
        string toolVersion,
        string targetSelector,
        string vantage,
        PentestImportDocument nmap,
        IReadOnlyList<PentestImportDocument> supplementalInputs,
        SystemSnapshot snapshot,
        IReadOnlyDictionary<VerificationEndpointKey, VerificationEndpointKey> portMappings,
        bool firewallRequested)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolVersion);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetSelector);
        ArgumentException.ThrowIfNullOrWhiteSpace(vantage);
        ArgumentNullException.ThrowIfNull(nmap);
        ArgumentNullException.ThrowIfNull(supplementalInputs);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(portMappings);

        if (!string.Equals(nmap.Source, "nmap_xml", StringComparison.Ordinal))
        {
            throw new VerificationInputException("verify requires an Nmap XML document as its primary input.");
        }

        var selection = SelectTarget(nmap, targetSelector);
        var aliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            NormalizeHost(targetSelector),
            NormalizeHost(selection.ImportedTarget),
        };
        var unassertedHostnameAliases = selection.WasHostnameSelection
            ? 0
            : selection.Endpoints.Select(static endpoint => endpoint.Hostname)
                .Where(static hostname => !string.IsNullOrWhiteSpace(hostname))
                .Select(static hostname => NormalizeHost(hostname!))
                .Where(static hostname => hostname.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

        var diagnostics = new List<VerificationDiagnostic>();
        AddInputDiagnostics(nmap, diagnostics);
        foreach (var input in supplementalInputs)
        {
            AddInputDiagnostics(input, diagnostics);
        }

        foreach (var diagnostic in snapshot.Diagnostics)
        {
            diagnostics.Add(new(diagnostic.Code, diagnostic.Message));
        }

        if (unassertedHostnameAliases > 0)
        {
            diagnostics.Add(new(
                "verify_hostname_alias_not_asserted",
                $"{unassertedHostnameAliases:N0} Nmap hostname aliases were not used to associate supplemental findings because the operator selected an exact IP address."));
        }

        var matchingFindings = new List<ImportedFinding>();
        var ignoredFindingCount = 0;
        foreach (var document in new[] { nmap }.Concat(supplementalInputs))
        {
            foreach (var finding in document.Findings)
            {
                if (aliases.Contains(NormalizeHost(finding.Target)))
                {
                    matchingFindings.Add(finding);
                }
                else
                {
                    ignoredFindingCount++;
                }
            }
        }

        if (ignoredFindingCount > 0)
        {
            diagnostics.Add(new(
                "verify_out_of_target_evidence_ignored",
                $"{ignoredFindingCount:N0} imported finding records did not match the selected target and were not correlated."));
        }

        var importedGroups = selection.Endpoints
            .GroupBy(
                static endpoint => new VerificationEndpointKey(ParseProtocol(endpoint.Protocol), endpoint.Port))
            .OrderBy(static group => group.Key.Protocol)
            .ThenBy(static group => group.Key.Port)
            .ToArray();
        if (importedGroups.Length > MaximumOutputEndpoints)
        {
            throw new VerificationInputException(
                $"The selected Nmap target exceeds the {MaximumOutputEndpoints:N0}-endpoint verification limit.");
        }

        var importedKeys = importedGroups.Select(static group => group.Key).ToHashSet();
        var importedPorts = importedKeys.Select(static key => key.Port).ToHashSet();
        var unusedMapping = portMappings.Keys.FirstOrDefault(key => !importedKeys.Contains(key));
        if (!unusedMapping.Equals(default(VerificationEndpointKey))
            && !importedKeys.Contains(unusedMapping))
        {
            throw new VerificationInputException(
                $"Port mapping for {unusedMapping} does not match an endpoint on the selected Nmap target.");
        }

        if (matchingFindings.Count > MaximumSelectedFindings)
        {
            throw new VerificationInputException(
                $"The selected target exceeds the {MaximumSelectedFindings:N0}-finding verification limit; split the evidence into bounded runs.");
        }

        var targetFindings = new List<ImportedFinding>();
        var endpointFindings = new Dictionary<FindingEndpoint, List<ImportedFinding>>();
        var findingMemberships = 0;
        var findingsWithoutNmapEndpoint = 0;
        var findingsWithUnresolvedProtocol = 0;
        var findingEndpointConflicts = 0;
        foreach (var finding in matchingFindings)
        {
            findingMemberships = checked(findingMemberships + Math.Max(1, finding.AdvisoryIds.Count));
            if (findingMemberships > MaximumFindingMemberships)
            {
                throw new VerificationInputException(
                    $"The selected target exceeds the {MaximumFindingMemberships:N0}-advisory-membership verification limit; split the evidence into bounded runs.");
            }

            var resolution = ResolveFindingEndpoint(finding);
            if (resolution.HasConflict)
            {
                targetFindings.Add(finding);
                findingEndpointConflicts++;
                continue;
            }

            var resolved = resolution.Endpoint;
            var representedByNmap = resolved?.Protocol is not null
                && importedKeys.Contains(new(resolved.Value.Protocol.Value, resolved.Value.Port));
            if (!representedByNmap)
            {
                targetFindings.Add(finding);
                if (resolved?.Protocol is null && resolved is not null && importedPorts.Contains(resolved.Value.Port))
                {
                    findingsWithUnresolvedProtocol++;
                }
                else if (resolved is not null)
                {
                    findingsWithoutNmapEndpoint++;
                }

                continue;
            }

            if (!endpointFindings.TryGetValue(resolved!.Value, out var indexed))
            {
                indexed = [];
                endpointFindings.Add(resolved.Value, indexed);
            }

            indexed.Add(finding);
        }

        if (findingsWithoutNmapEndpoint > 0)
        {
            diagnostics.Add(new(
                "verify_finding_endpoint_not_in_nmap",
                $"{findingsWithoutNmapEndpoint:N0} selected-target findings referenced endpoints absent from the Nmap input and were retained as target-level observations."));
        }


        if (findingsWithUnresolvedProtocol > 0)
        {
            diagnostics.Add(new(
                "verify_finding_protocol_unresolved",
                $"{findingsWithUnresolvedProtocol:N0} selected-target findings had a port but no defensible transport protocol and were retained as target-level observations."));
        }

        if (findingEndpointConflicts > 0)
        {
            diagnostics.Add(new(
                "verify_finding_endpoint_conflict",
                $"{findingEndpointConflicts:N0} selected-target findings contained conflicting port or transport fields and were retained as target-level observations."));
        }

        var targetFindingGroups = GroupFindings(targetFindings, FindingCorrelation.ScannerOnly);

        var baseCollectorsComplete = BaseCollectorsComplete(snapshot, firewallRequested);
        var inputsComplete = nmap.IsComplete
            && supplementalInputs.All(static input => input.IsComplete)
            && findingEndpointConflicts == 0;
        var selectedLiveEvidenceComplete = baseCollectorsComplete;
        var endpoints = new List<VerifiedExposureEndpoint>();
        foreach (var group in importedGroups)
        {
            var externalKey = group.Key;
            var localKey = portMappings.TryGetValue(externalKey, out var mapped) ? mapped : externalKey;
            var localListeners = snapshot.Listeners
                .Where(listener => listener.Protocol == localKey.Protocol && listener.LocalPort == localKey.Port)
                .OrderBy(static listener => listener.BindScope)
                .ThenBy(static listener => listener.Family)
                .ThenBy(static listener => listener.LocalAddress, StringComparer.Ordinal)
                .Select(ToLocalListener)
                .ToArray();
            var findingsForEndpoint = new List<ImportedFinding>();
            if (endpointFindings.TryGetValue(new(externalKey.Protocol, externalKey.Port), out var protocolFindings))
            {
                findingsForEndpoint.AddRange(protocolFindings);
            }

            var localEvidenceComplete = LocalEvidenceComplete(localListeners, firewallRequested);
            selectedLiveEvidenceComplete &= localEvidenceComplete;
            var correlation = Correlate(
                group,
                localListeners,
                inputsComplete,
                baseCollectorsComplete && localEvidenceComplete);
            var limitations = Limitations(correlation, group, localListeners, selection.WasHostnameSelection);

            // Closed ports with no current listener or finding add no useful evidence and can make full-range
            // Nmap reports unnecessarily large. Explicit negative evidence is retained when it conflicts with
            // a local listener or has a scanner finding attached.
            if (group.All(static endpoint => endpoint.State == "closed")
                && localListeners.Length == 0
                && findingsForEndpoint.Count == 0)
            {
                continue;
            }

            endpoints.Add(new(
                externalKey.Protocol.ToString().ToLowerInvariant(),
                externalKey.Port,
                localKey.Port,
                correlation,
                group.Select(static endpoint => new OutsideEndpointObservation(
                        "nmap_xml",
                        endpoint.Target,
                        endpoint.Hostname,
                        endpoint.State,
                        endpoint.StateReason,
                        endpoint.Service))
                    .OrderBy(static item => item.State, StringComparer.Ordinal)
                    .ToArray(),
                localListeners,
                GroupFindings(
                    findingsForEndpoint,
                    FindingCorrelationFor(correlation, selection.WasHostnameSelection)),
                limitations));
        }

        var inputs = new List<VerificationInput>
        {
            ToInput(nmap),
        };
        inputs.AddRange(supplementalInputs.Select(ToInput));
        inputs.Add(new(
            VerificationInputKind.LiveWindows,
            null,
            null,
            null,
            snapshot.ToolVersion,
            selectedLiveEvidenceComplete,
            snapshot.GeneratedAt));

        var summary = Summarize(
            endpoints,
            targetFindingGroups,
            importedGroups.Length,
            importedGroups.Count(static group => group.Any(static endpoint => endpoint.State == "open")),
            inputsComplete && selectedLiveEvidenceComplete);
        return new(
            ExposureVerificationReport.CurrentSchemaVersion,
            toolVersion,
            VerificationPrivacyMode.Private,
            DateTimeOffset.UtcNow,
            new(
                selection.ImportedTarget,
                true,
                vantage,
                portMappings.OrderBy(static pair => pair.Key.Protocol)
                    .ThenBy(static pair => pair.Key.Port)
                    .Select(static pair => new VerificationPortMapping(
                        pair.Key.Protocol.ToString().ToLowerInvariant(),
                        pair.Key.Port,
                        pair.Value.Port))
                    .ToArray()),
            inputs,
            endpoints,
            targetFindingGroups,
            summary,
            diagnostics.OrderBy(static diagnostic => diagnostic.Code, StringComparer.Ordinal).ToArray(),
            ClaimBoundary)
        {
            PrivateRedactionAliases = BuildPrivateRedactionAliases(
                selection.Endpoints
                    .SelectMany(static endpoint => new[] { endpoint.Target, endpoint.Hostname })
                    .Concat(supplementalInputs
                        .SelectMany(static document => document.Endpoints)
                        .Where(endpoint => aliases.Contains(NormalizeHost(endpoint.Target)))
                        .SelectMany(static endpoint => new[] { endpoint.Target, endpoint.Hostname }))
                    .Concat(supplementalInputs
                        .SelectMany(static document => document.PrivateHostAliases)
                        .Where(alias => aliases.Contains(NormalizeHost(alias.Target)))
                        .SelectMany(static alias => new[] { alias.Target, alias.Hostname }))
                    .Concat(matchingFindings.Select(static finding => finding.Target))
                    .Append(targetSelector)),
        };
    }

    internal static TargetSelection SelectTarget(PentestImportDocument nmap, string targetSelector)
    {
        var selector = NormalizeHost(targetSelector);
        if (selector.Length == 0)
        {
            throw new VerificationInputException("--target must be an IP address or hostname present in the Nmap input.");
        }

        var exactAddressMatches = nmap.Endpoints
            .Where(endpoint => string.Equals(NormalizeHost(endpoint.Target), selector, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (exactAddressMatches.Length > 0)
        {
            var exactTargets = exactAddressMatches.Select(static endpoint => endpoint.Target)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (exactTargets.Length != 1)
            {
                throw new VerificationInputException("The Nmap target selector matched more than one imported address.");
            }

            return new(exactTargets[0], exactAddressMatches, false);
        }

        var hostnameMatches = nmap.Endpoints
            .Where(endpoint => !string.IsNullOrWhiteSpace(endpoint.Hostname)
                && string.Equals(NormalizeHost(endpoint.Hostname), selector, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var hostnameTargets = hostnameMatches.Select(static endpoint => endpoint.Target)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (hostnameTargets.Length == 0)
        {
            throw new VerificationInputException(
                $"Target '{targetSelector}' was not found in the imported Nmap endpoint records.");
        }

        if (hostnameTargets.Length > 1)
        {
            throw new VerificationInputException(
                $"Hostname '{targetSelector}' maps to multiple imported addresses; select one exact IP address.");
        }

        return new(hostnameTargets[0], hostnameMatches, true);
    }

    internal sealed record TargetSelection(
        string ImportedTarget,
        IReadOnlyList<ImportedEndpoint> Endpoints,
        bool WasHostnameSelection);

    private static ExposureCorrelation Correlate(
        IEnumerable<ImportedEndpoint> outside,
        IReadOnlyList<VerificationLocalListener> local,
        bool inputsComplete,
        bool collectorsComplete)
    {
        if (!inputsComplete || !collectorsComplete)
        {
            return ExposureCorrelation.Inconclusive;
        }

        var states = outside.Select(static item => item.State).Distinct(StringComparer.Ordinal).ToArray();
        if (states.Length != 1)
        {
            return ExposureCorrelation.Inconclusive;
        }

        var nonLoopback = local.Any(static item => item.BindScope is BindScope.Interface or BindScope.Wildcard);
        var loopback = local.Any(static item => item.BindScope == BindScope.Loopback);
        var unknown = local.Any(static item => item.BindScope == BindScope.Unknown);
        return states[0] switch
        {
            "open" when nonLoopback => ExposureCorrelation.CorrelatedOpen,
            "open" when unknown => ExposureCorrelation.Inconclusive,
            "open" when loopback => ExposureCorrelation.LoopbackMismatch,
            "open" => ExposureCorrelation.OutsideOnly,
            "closed" when local.Count > 0 => ExposureCorrelation.OutsideNegativeLocalPresent,
            "filtered" or "unfiltered" or "closed|filtered" when local.Count > 0 =>
                ExposureCorrelation.OutsideNegativeLocalPresent,
            "closed" => ExposureCorrelation.ConsistentAbsent,
            _ => ExposureCorrelation.Inconclusive,
        };
    }

    private static IReadOnlyList<string> Limitations(
        ExposureCorrelation correlation,
        IEnumerable<ImportedEndpoint> outside,
        IReadOnlyList<VerificationLocalListener> local,
        bool hostnameSelection)
    {
        var limitations = new List<string>
        {
            "The imported scan and live Windows collection were not simultaneous.",
        };
        if (hostnameSelection)
        {
            limitations.Add("The operator selected the target by hostname; PortCVE joined it to one imported address.");
        }

        if (outside.Select(static item => item.State).Distinct(StringComparer.Ordinal).Count() > 1)
        {
            limitations.Add("Imported observations disagree on the external port state.");
        }

        if (local.Count > 1)
        {
            limitations.Add("Multiple live listeners match the mapped local endpoint; all candidates are retained.");
        }

        switch (correlation)
        {
            case ExposureCorrelation.CorrelatedOpen:
                limitations.Add("A matching listener supports owner attribution but does not prove packet-path identity.");
                break;
            case ExposureCorrelation.OutsideOnly:
                limitations.Add("Possible causes include stale evidence, NAT, a proxy, a forwarder, a stopped service, or an incorrect host association.");
                break;
            case ExposureCorrelation.LoopbackMismatch:
                limitations.Add("The imported open port maps only to a loopback listener in the live snapshot.");
                break;
            case ExposureCorrelation.OutsideNegativeLocalPresent:
                limitations.Add("A live local listener was present, but the imported vantage did not report the mapped external port as open.");
                break;
            case ExposureCorrelation.Inconclusive:
                limitations.Add("Incomplete, conflicting, or non-definitive evidence prevents a stronger correlation.");
                break;
        }

        return limitations;
    }

    private static VerificationLocalListener ToLocalListener(ListenerEvidence listener)
    {
        var locked = LockfileService.ToLockedListener(listener);
        return new(
            listener.Family,
            listener.BindScope,
            listener.LocalAddress,
            listener.LocalPort,
            locked.OwnerIdentity,
            locked.OwnerIdentityStrength,
            listener.Owner.ImageName,
            listener.Owner.Services,
            (listener.ContainerExposures ?? [])
                .Select(static container => container.ImageId ?? container.Image)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            listener.HostPolicy.Verdict,
            listener.HostPolicy.Confidence,
            listener.Limitations.Concat(listener.Owner.Limitations).Distinct(StringComparer.Ordinal).ToArray());
    }

    private static IReadOnlyList<VerificationFindingGroup> GroupFindings(
        IReadOnlyList<ImportedFinding> findings,
        FindingCorrelation correlation)
    {
        var observations = findings.Select(finding => new
        {
            Finding = finding,
            Keys = finding.AdvisoryIds.Count > 0
                ? finding.AdvisoryIds.Select(static advisory => $"cve:{advisory.ToUpperInvariant()}").ToArray()
                : [$"finding:{finding.Source}:{finding.FindingId}"],
        });
        return observations
            .SelectMany(static item => item.Keys.Select(key => new { key, item.Finding }))
            .GroupBy(static item => item.key, StringComparer.Ordinal)
            .OrderBy(static group => group.Key, StringComparer.Ordinal)
            .Select(group =>
            {
                var groupedAdvisoryId = group.Key.StartsWith("cve:", StringComparison.Ordinal)
                    ? group.Key[4..]
                    : null;
                var groupObservations = group.Select(item => ToFindingObservation(item.Finding, groupedAdvisoryId))
                    .GroupBy(static item => (item.Source, item.FindingId, item.SourceRecordSha256))
                    .Select(static observations => observations.First())
                    .OrderBy(static item => item.Source, StringComparer.Ordinal)
                    .ThenBy(static item => item.FindingId, StringComparer.Ordinal)
                    .ToArray();
                var advisoryIds = groupObservations.SelectMany(static item => item.AdvisoryIds)
                    .Distinct(StringComparer.Ordinal)
                    .Order(StringComparer.Ordinal)
                    .ToArray();
                var highest = groupObservations.OrderByDescending(static item => SeverityRank(item.Severity)).First();
                return new VerificationFindingGroup(
                    group.Key,
                    highest.Title,
                    NormalizeSeverity(highest.Severity),
                    advisoryIds,
                    correlation,
                    "not_assessed",
                    groupObservations);
            })
            .ToArray();
    }

    private static VerificationFindingObservation ToFindingObservation(
        ImportedFinding finding,
        string? groupedAdvisoryId) => new(
        finding.Source,
        finding.FindingId,
        finding.Title,
        NormalizeSeverity(finding.Severity),
        finding.ClaimStatus,
        finding.EvidenceStrength,
        groupedAdvisoryId is null ? [] : [groupedAdvisoryId],
        finding.SourceRecordSha256,
        finding.Matcher);

    private static FindingEndpointResolution ResolveFindingEndpoint(ImportedFinding finding)
    {
        var targetPort = InferPort(finding.Target);
        if (finding.Port is not null && targetPort is not null && finding.Port != targetPort)
        {
            return new(null, true);
        }

        var port = finding.Port ?? targetPort;
        if (port is null)
        {
            return new(null, false);
        }

        var explicitProtocol = NormalizeExplicitFindingProtocol(finding.Protocol, port.Value);
        var targetProtocol = InferTargetProtocol(finding.Target);
        if (explicitProtocol is not null && targetProtocol is not null && explicitProtocol != targetProtocol)
        {
            return new(null, true);
        }

        var protocol = string.IsNullOrWhiteSpace(finding.Protocol)
            ? targetProtocol
            : explicitProtocol;
        return new(new(protocol, port.Value), false);
    }

    private static int? InferPort(string target)
    {
        return Uri.TryCreate(target, UriKind.Absolute, out var uri)
            && uri.Port is >= 1 and <= 65535
            ? uri.Port
            : null;
    }

    private static TransportProtocol? NormalizeExplicitFindingProtocol(string? protocol, int port)
    {
        var value = protocol?.ToLowerInvariant();
        if (value == "udp" || value == "dns" && port == 53)
        {
            return TransportProtocol.Udp;
        }

        if (value is "tcp" or "http" or "https" or "tls" or "ssl" or "ssh" or "ftp" or "smtp" or "pop3" or "imap")
        {
            return TransportProtocol.Tcp;
        }

        return null;
    }

    private static TransportProtocol? InferTargetProtocol(string target)
    {
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri))
        {
            return null;
        }

        return uri.Scheme.ToLowerInvariant() switch
        {
            "http" or "https" or "tls" or "ssl" or "ssh" or "ftp" or "smtp" or "pop3" or "imap" or "tcp" =>
                TransportProtocol.Tcp,
            "udp" => TransportProtocol.Udp,
            "dns" when uri.Port == 53 => TransportProtocol.Udp,
            _ => null,
        };
    }

    private static TransportProtocol ParseProtocol(string value) => value switch
    {
        "tcp" => TransportProtocol.Tcp,
        "udp" => TransportProtocol.Udp,
        _ => throw new VerificationInputException($"Unsupported imported endpoint protocol '{value}'."),
    };

    private static string NormalizeHost(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        var value = raw.Trim();
        if (Uri.TryCreate(value, UriKind.Absolute, out var absolute)
            && !string.IsNullOrWhiteSpace(absolute.Host))
        {
            value = absolute.Host;
        }
        else if (Uri.TryCreate($"tcp://{value}", UriKind.Absolute, out var endpoint)
            && !string.IsNullOrWhiteSpace(endpoint.Host))
        {
            value = endpoint.Host;
        }

        value = value.Trim('[', ']').TrimEnd('.');
        if (IPAddress.TryParse(value, out var address))
        {
            return address.AddressFamily == AddressFamily.InterNetworkV6
                ? address.ToString().ToLowerInvariant()
                : address.ToString();
        }

        try
        {
            return new IdnMapping().GetAscii(value).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return string.Empty;
        }
    }

    private static IEnumerable<string> RedactionAliases(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            yield break;
        }

        var value = raw.Trim();

        var rawUriHost = ExtractRawUriHost(value);
        if (rawUriHost is not null)
        {
            yield return rawUriHost;
            if (IPAddress.TryParse(rawUriHost, out var rawAddress)
                && rawAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                yield return $"[{rawUriHost}]";
            }
        }

        else if (IsBareTarget(value))
        {
            yield return value.Trim('[', ']');
        }

        if (Uri.TryCreate(value, UriKind.Absolute, out var uri)
            && !string.IsNullOrWhiteSpace(uri.Host))
        {
            foreach (var host in new[]
            {
                uri.Host,
                uri.IdnHost,
                uri.DnsSafeHost,
                uri.GetComponents(UriComponents.Host, UriFormat.Unescaped),
                uri.GetComponents(UriComponents.Host, UriFormat.UriEscaped),
            })
            {
                if (string.IsNullOrWhiteSpace(host))
                {
                    continue;
                }

                var withoutBrackets = host.Trim('[', ']');
                yield return host;
                yield return withoutBrackets;
                if (IPAddress.TryParse(withoutBrackets, out var address)
                    && address.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    yield return $"[{withoutBrackets}]";
                }
            }
        }

        var normalized = NormalizeHost(value);
        if (normalized.Length > 0)
        {
            yield return normalized;
            if (IPAddress.TryParse(normalized, out var normalizedAddress)
                && normalizedAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                yield return $"[{normalized}]";
            }
            else
            {
                string? unicode = null;
                try
                {
                    unicode = new IdnMapping().GetUnicode(normalized);
                }
                catch (ArgumentException)
                {
                    // NormalizeHost already supplied the safe ASCII form.
                }

                if (!string.IsNullOrWhiteSpace(unicode))
                {
                    yield return unicode;
                    yield return unicode.Normalize(NormalizationForm.FormC);
                    yield return unicode.Normalize(NormalizationForm.FormD);
                }
            }
        }
    }

    private static IReadOnlyList<string> BuildPrivateRedactionAliases(IEnumerable<string?> rawValues)
    {
        var aliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawValue in rawValues)
        {
            foreach (var alias in RedactionAliases(rawValue))
            {
                if (string.IsNullOrWhiteSpace(alias) || !aliases.Add(alias))
                {
                    continue;
                }

                if (aliases.Count > MaximumPrivateRedactionAliases)
                {
                    throw new VerificationInputException(
                        $"The selected evidence exceeds the {MaximumPrivateRedactionAliases:N0}-alias privacy limit; split the evidence into bounded runs.");
                }
            }
        }

        return aliases.OrderByDescending(static alias => alias.Length)
            .ThenBy(static alias => alias, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool IsBareTarget(string value)
    {
        if (value.IndexOfAny(['/', '?', '#', '@']) >= 0)
        {
            return false;
        }

        if (value.StartsWith("[", StringComparison.Ordinal) && value.EndsWith("]", StringComparison.Ordinal))
        {
            return true;
        }

        var colonCount = value.Count(static character => character == ':');
        return colonCount == 0 || colonCount > 1;
    }

    private static string? ExtractRawUriHost(string value)
    {
        var schemeSeparator = value.IndexOf("://", StringComparison.Ordinal);
        if (schemeSeparator < 1)
        {
            return null;
        }

        var authorityStart = schemeSeparator + 3;
        var authorityEnd = value.IndexOfAny(['/', '?', '#'], authorityStart);
        var authority = authorityEnd < 0
            ? value[authorityStart..]
            : value[authorityStart..authorityEnd];
        var userInfoEnd = authority.LastIndexOf('@');
        if (userInfoEnd >= 0)
        {
            authority = authority[(userInfoEnd + 1)..];
        }

        if (authority.StartsWith("[", StringComparison.Ordinal))
        {
            var closingBracket = authority.IndexOf(']');
            return closingBracket > 1 ? authority[1..closingBracket] : null;
        }

        var portSeparator = authority.LastIndexOf(':');
        if (portSeparator > 0
            && int.TryParse(authority[(portSeparator + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out _))
        {
            authority = authority[..portSeparator];
        }

        return authority.Length == 0 ? null : authority;
    }

    private static FindingCorrelation FindingCorrelationFor(
        ExposureCorrelation correlation,
        bool hostnameSelection) => correlation switch
        {
            ExposureCorrelation.CorrelatedOpen when !hostnameSelection => FindingCorrelation.OwnerCorroborated,
            ExposureCorrelation.CorrelatedOpen => FindingCorrelation.OwnerAmbiguous,
            ExposureCorrelation.OutsideNegativeLocalPresent or ExposureCorrelation.LoopbackMismatch =>
                FindingCorrelation.OwnerAmbiguous,
            ExposureCorrelation.OutsideOnly => FindingCorrelation.ScannerOnly,
            _ => FindingCorrelation.Inconclusive,
        };

    private static VerificationInput ToInput(PentestImportDocument document) => new(
        document.Source switch
        {
            "nmap_xml" => VerificationInputKind.NmapXml,
            "nuclei_jsonl" => VerificationInputKind.NucleiJsonl,
            "nessus_xml" => VerificationInputKind.NessusXml,
            _ => throw new VerificationInputException($"Unsupported verification input source '{document.Source}'."),
        },
        document.Input.FileName,
        document.Input.SizeBytes,
        document.Input.Sha256,
        document.SourceVersion,
        document.IsComplete,
        null);

    private static void AddInputDiagnostics(
        PentestImportDocument document,
        ICollection<VerificationDiagnostic> diagnostics)
    {
        foreach (var diagnostic in document.Diagnostics)
        {
            diagnostics.Add(new(diagnostic.Code, diagnostic.Message));
        }
    }

    private static bool BaseCollectorsComplete(SystemSnapshot snapshot, bool firewallRequested)
    {
        var socketsComplete = snapshot.Collectors.Any(static report =>
            report.Name == "sockets" && report.Status == CollectorStatus.Complete);
        var firewallComplete = !firewallRequested || snapshot.Collectors.Any(static report =>
            report.Name == "windows_firewall" && report.Status == CollectorStatus.Complete);
        return socketsComplete && firewallComplete;
    }

    private static bool LocalEvidenceComplete(
        IReadOnlyList<VerificationLocalListener> listeners,
        bool firewallRequested) => listeners.All(listener =>
            listener.BindScope != BindScope.Unknown
            && listener.OwnerIdentityStrength is OwnerIdentityStrength.Sha256
                or OwnerIdentityStrength.ContainerImage
                or OwnerIdentityStrength.Service
                or OwnerIdentityStrength.Kernel
            && (!firewallRequested
                || (listener.BindScope == BindScope.Loopback
                    && listener.HostPolicy == FirewallVerdict.NotEvaluated)
                || (listener.HostPolicy is FirewallVerdict.Allow or FirewallVerdict.Block or FirewallVerdict.Disabled
                    && listener.HostPolicyConfidence is Confidence.High or Confidence.Medium)));

    private static ExposureVerificationSummary Summarize(
        IReadOnlyList<VerifiedExposureEndpoint> endpoints,
        IReadOnlyList<VerificationFindingGroup> targetFindings,
        int outsideEndpointCount,
        int outsideOpenCount,
        bool evidenceComplete)
    {
        var findings = endpoints.SelectMany(static endpoint => endpoint.Findings).Concat(targetFindings).ToArray();
        return new(
            outsideEndpointCount,
            outsideOpenCount,
            endpoints.Count(static endpoint => endpoint.Correlation == ExposureCorrelation.CorrelatedOpen),
            endpoints.Count(static endpoint => endpoint.Correlation == ExposureCorrelation.OutsideOnly),
            endpoints.Count(static endpoint => endpoint.Correlation == ExposureCorrelation.LoopbackMismatch),
            endpoints.Count(static endpoint => endpoint.Correlation == ExposureCorrelation.OutsideNegativeLocalPresent),
            endpoints.Count(static endpoint => endpoint.Correlation == ExposureCorrelation.ConsistentAbsent),
            endpoints.Count(static endpoint => endpoint.Correlation == ExposureCorrelation.Inconclusive),
            findings.Length,
            findings.Count(static finding => finding.HighestReportedSeverity == "critical"),
            findings.Count(static finding => finding.HighestReportedSeverity == "high"),
            evidenceComplete && endpoints.All(static endpoint => endpoint.Correlation != ExposureCorrelation.Inconclusive));
    }

    private static string NormalizeSeverity(string value) => value.ToLowerInvariant() switch
    {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "info" => "info",
        _ => "unknown",
    };

    private static int SeverityRank(string value) => NormalizeSeverity(value) switch
    {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    };

    private readonly record struct FindingEndpoint(TransportProtocol? Protocol, int Port);

    private readonly record struct FindingEndpointResolution(FindingEndpoint? Endpoint, bool HasConflict);
}
