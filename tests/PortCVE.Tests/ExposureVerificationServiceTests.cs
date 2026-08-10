using PortCVE.Domain;
using PortCVE.Output;
using PortCVE.Remote.Imports;
using PortCVE.Verification;

namespace PortCVE.Tests;

public sealed class ExposureVerificationServiceTests
{
    private static readonly IReadOnlyDictionary<VerificationEndpointKey, VerificationEndpointKey> NoMappings =
        new Dictionary<VerificationEndpointKey, VerificationEndpointKey>();

    [Fact]
    public void SelectTarget_ExactAddressRetainsOnlyThatHost()
    {
        var document = Nmap(
            [
                Endpoint("192.0.2.10", 443, hostname: "web.example"),
                Endpoint("192.0.2.10", 8443, hostname: "web.example"),
                Endpoint("192.0.2.11", 443, hostname: "other.example"),
            ]);

        var selection = ExposureVerificationService.SelectTarget(document, "192.0.2.10");

        Assert.Equal("192.0.2.10", selection.ImportedTarget);
        Assert.False(selection.WasHostnameSelection);
        Assert.Equal([443, 8443], selection.Endpoints.Select(static endpoint => endpoint.Port));
    }

    [Fact]
    public void SelectTarget_NormalizedHostnameResolvesOneImportedAddress()
    {
        var document = Nmap(
            [
                Endpoint("192.0.2.10", 443, hostname: "Web.Example."),
                Endpoint("192.0.2.10", 8443, hostname: "Web.Example."),
            ]);

        var selection = ExposureVerificationService.SelectTarget(document, "web.example");

        Assert.Equal("192.0.2.10", selection.ImportedTarget);
        Assert.True(selection.WasHostnameSelection);
        Assert.Equal(2, selection.Endpoints.Count);
    }

    [Fact]
    public void SelectTarget_MissingTargetFailsClosed()
    {
        var exception = Assert.Throws<VerificationInputException>(() =>
            ExposureVerificationService.SelectTarget(
                Nmap([Endpoint("192.0.2.10", 443, hostname: "web.example")]),
                "missing.example"));

        Assert.Contains("not found", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SelectTarget_AmbiguousHostnameRequiresExactAddress()
    {
        var document = Nmap(
            [
                Endpoint("192.0.2.10", 443, hostname: "shared.example"),
                Endpoint("192.0.2.11", 443, hostname: "shared.example"),
            ]);

        var exception = Assert.Throws<VerificationInputException>(() =>
            ExposureVerificationService.SelectTarget(document, "shared.example"));

        Assert.Contains("multiple", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("exact IP", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_CorrelatesOutsideAndLiveStatesAndRetainsEveryMatchingListener()
    {
        var nmap = Nmap(
            [
                Endpoint("192.0.2.10", 443, state: "open"),
                Endpoint("192.0.2.10", 80, state: "open"),
                Endpoint("192.0.2.10", 22, state: "open"),
                Endpoint("192.0.2.10", 445, state: "filtered"),
                Endpoint("192.0.2.10", 53, protocol: "udp", state: "open|filtered"),
            ]);
        var snapshot = Snapshot(
            [
                Listener(443, BindScope.Wildcard, IpFamily.Ipv4, "0.0.0.0", "web-v4.exe"),
                Listener(443, BindScope.Interface, IpFamily.Ipv6, "2001:db8::10", "web-v6.exe"),
                Listener(22, BindScope.Loopback, IpFamily.Ipv4, "127.0.0.1", "ssh.exe"),
                Listener(445, BindScope.Interface, IpFamily.Ipv4, "192.0.2.10", "smb.exe"),
                Listener(53, BindScope.Wildcard, IpFamily.Ipv4, "0.0.0.0", "dns.exe", TransportProtocol.Udp),
            ]);

        var report = Verify(nmap, snapshot);

        Assert.Equal(VerificationPrivacyMode.Private, report.PrivacyMode);
        Assert.Equal(
            [
                ("tcp", 22),
                ("tcp", 80),
                ("tcp", 443),
                ("tcp", 445),
                ("udp", 53),
            ],
            report.Endpoints.Select(static endpoint => (endpoint.Protocol, endpoint.ExternalPort)));
        Assert.Equal(ExposureCorrelation.LoopbackMismatch, Find(report, "tcp", 22).Correlation);
        Assert.Equal(ExposureCorrelation.OutsideOnly, Find(report, "tcp", 80).Correlation);
        Assert.Equal(ExposureCorrelation.CorrelatedOpen, Find(report, "tcp", 443).Correlation);
        Assert.Equal(
            ExposureCorrelation.OutsideNegativeLocalPresent,
            Find(report, "tcp", 445).Correlation);
        Assert.Equal(ExposureCorrelation.Inconclusive, Find(report, "udp", 53).Correlation);

        var web = Find(report, "tcp", 443);
        Assert.Equal(2, web.LocalListeners.Count);
        Assert.Contains(web.LocalListeners, static listener =>
            listener.Family == IpFamily.Ipv4 && listener.BindScope == BindScope.Wildcard);
        Assert.Contains(web.LocalListeners, static listener =>
            listener.Family == IpFamily.Ipv6 && listener.BindScope == BindScope.Interface);
        Assert.Contains(web.Limitations, static limitation =>
            limitation.Contains("Multiple live listeners", StringComparison.Ordinal));

        Assert.Equal(1, report.Summary.CorrelatedOpenCount);
        Assert.Equal(1, report.Summary.OutsideOnlyCount);
        Assert.Equal(1, report.Summary.LoopbackMismatchCount);
        Assert.Equal(1, report.Summary.OutsideNegativeLocalPresentCount);
        Assert.Equal(1, report.Summary.InconclusiveCount);
        Assert.False(report.Summary.IsComplete);
    }

    [Fact]
    public void Verify_ExplicitPortMapJoinsNatOrForwardedEndpoint()
    {
        var mappings = PortMappingParser.Parse("tcp/443=tcp/8443");
        var report = Verify(
            Nmap([Endpoint("192.0.2.10", 443)]),
            Snapshot([Listener(8443, BindScope.Wildcard, IpFamily.Ipv4, "0.0.0.0", "proxy.exe")]),
            mappings: mappings);

        var endpoint = Assert.Single(report.Endpoints);
        Assert.Equal(443, endpoint.ExternalPort);
        Assert.Equal(8443, endpoint.LocalPort);
        Assert.Equal(ExposureCorrelation.CorrelatedOpen, endpoint.Correlation);
        var mapping = Assert.Single(report.Association.PortMappings);
        Assert.Equal("tcp", mapping.Protocol);
        Assert.Equal(443, mapping.ExternalPort);
        Assert.Equal(8443, mapping.LocalPort);
    }

    [Fact]
    public void Verify_UnusedPortMapFailsClosed()
    {
        var exception = Assert.Throws<VerificationInputException>(() => Verify(
            Nmap([Endpoint("192.0.2.10", 443)]),
            Snapshot([]),
            mappings: PortMappingParser.Parse("tcp/80=tcp/8080")));

        Assert.Contains("does not match", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_UnknownBindScopeCannotCorroborateOutsideOpenPort()
    {
        var report = Verify(
            Nmap([Endpoint("192.0.2.10", 443)]),
            Snapshot([Listener(443, BindScope.Unknown, IpFamily.Ipv4, "192.0.2.10", "unknown.exe")]));

        Assert.Equal(ExposureCorrelation.Inconclusive, Assert.Single(report.Endpoints).Correlation);
        Assert.False(report.Summary.IsComplete);
    }

    [Fact]
    public void Verify_SummaryCountsImportedClosedEndpointsEvenWhenTheyAreNotRetained()
    {
        var report = Verify(
            Nmap([Endpoint("192.0.2.10", 80, state: "closed")]),
            Snapshot([]));

        Assert.Empty(report.Endpoints);
        Assert.Equal(1, report.Summary.OutsideEndpointCount);
        Assert.Equal(0, report.Summary.OutsideOpenCount);
        Assert.True(report.Summary.IsComplete);
    }

    [Fact]
    public void Verify_IncompleteInputIsInconclusiveButUnrelatedOwnerGapsAreScoped()
    {
        var incompleteNmap = Nmap([Endpoint("192.0.2.10", 443)], isComplete: false);
        var incompleteSnapshot = Snapshot(
            [Listener(443, BindScope.Wildcard, IpFamily.Ipv4, "0.0.0.0", "web.exe")],
            ownerStatus: CollectorStatus.Partial);

        var inputReport = Verify(incompleteNmap, Snapshot(
            [Listener(443, BindScope.Wildcard, IpFamily.Ipv4, "0.0.0.0", "web.exe")]));
        var collectorReport = Verify(
            Nmap([Endpoint("192.0.2.10", 443)]),
            incompleteSnapshot);

        Assert.Equal(ExposureCorrelation.Inconclusive, Assert.Single(inputReport.Endpoints).Correlation);
        Assert.Equal(ExposureCorrelation.CorrelatedOpen, Assert.Single(collectorReport.Endpoints).Correlation);
        Assert.False(inputReport.Summary.IsComplete);
        Assert.True(collectorReport.Summary.IsComplete);
    }

    [Fact]
    public void Verify_SelectedWeakOwnerEvidenceMakesEndpointInconclusive()
    {
        var listener = Listener(443, BindScope.Wildcard, IpFamily.Ipv4, "0.0.0.0", "web.exe");
        listener = listener with
        {
            Owner = listener.Owner with { ImageSha256 = null, Services = [], IsComplete = false },
        };

        var report = Verify(
            Nmap([Endpoint("192.0.2.10", 443)]),
            Snapshot([listener], ownerStatus: CollectorStatus.Partial));

        Assert.Equal(ExposureCorrelation.Inconclusive, Assert.Single(report.Endpoints).Correlation);
        Assert.False(report.Summary.IsComplete);
    }

    [Fact]
    public void Verify_DeduplicatesNucleiAndNessusCveAndPreservesProvenance()
    {
        var nmap = Nmap([Endpoint("192.0.2.10", 443)]);
        var nuclei = Supplemental(
            "nuclei_jsonl",
            [Finding(
                "nuclei_jsonl",
                "tls-template",
                "Nuclei TLS finding",
                "high",
                "https://192.0.2.10:443",
                443,
                "https",
                ["CVE-2024-12345"],
                'b')]);
        var nessus = Supplemental(
            "nessus_xml",
            [Finding(
                "nessus_xml",
                "10001",
                "Nessus TLS finding",
                "critical",
                "192.0.2.10",
                443,
                "tcp",
                ["CVE-2024-12345"],
                'c')]);
        var snapshot = Snapshot(
            [Listener(443, BindScope.Wildcard, IpFamily.Ipv4, "0.0.0.0", "web.exe")]);

        var report = Verify(nmap, snapshot, [nuclei, nessus]);

        var endpoint = Assert.Single(report.Endpoints);
        var group = Assert.Single(endpoint.Findings);
        Assert.Equal("cve:CVE-2024-12345", group.FindingGroupId);
        Assert.Equal("critical", group.HighestReportedSeverity);
        Assert.Equal(FindingCorrelation.OwnerCorroborated, group.Correlation);
        Assert.Equal("not_assessed", group.Exploitability);
        Assert.Equal(["CVE-2024-12345"], group.AdvisoryIds);
        Assert.Equal(["nessus_xml", "nuclei_jsonl"], group.Observations.Select(static item => item.Source));
        Assert.Equal([new string('c', 64), new string('b', 64)],
            group.Observations.Select(static item => item.SourceRecordSha256));
        Assert.Equal(1, report.Summary.FindingGroupCount);
        Assert.Equal(1, report.Summary.CriticalCount);
        Assert.Equal(0, report.Summary.HighCount);

        var reversed = Verify(nmap, snapshot, [nessus, nuclei]);
        Assert.Equal(
            JsonOutput.Serialize(report.Endpoints),
            JsonOutput.Serialize(reversed.Endpoints));
    }

    [Fact]
    public void Verify_MultiCveRecordDoesNotCopyEveryCveIntoEveryGroupObservation()
    {
        var supplemental = Supplemental(
            "nessus_xml",
            [Finding(
                "nessus_xml",
                "multi-cve",
                "Multi-CVE finding",
                "high",
                "192.0.2.10",
                443,
                "tcp",
                ["CVE-2026-10001", "CVE-2026-10002"],
                'd')]);

        var report = Verify(
            Nmap([Endpoint("192.0.2.10", 443)]),
            Snapshot([Listener(443, BindScope.Wildcard, IpFamily.Ipv4, "0.0.0.0", "web.exe")]),
            [supplemental]);

        var findings = Assert.Single(report.Endpoints).Findings;
        Assert.Equal(2, findings.Count);
        Assert.All(findings, static finding =>
        {
            Assert.Single(finding.AdvisoryIds);
            Assert.Equal(finding.AdvisoryIds, Assert.Single(finding.Observations).AdvisoryIds);
        });
    }

    [Fact]
    public void Verify_KeepsPortlessTargetFindingAndQuarantinesOtherTargets()
    {
        var supplemental = Supplemental(
            "nuclei_jsonl",
            [
                Finding(
                    "nuclei_jsonl",
                    "host-observation",
                    "Target-level observation",
                    "medium",
                    "192.0.2.10",
                    null,
                    null,
                    [],
                    'd'),
                Finding(
                    "nuclei_jsonl",
                    "other-target",
                    "Out-of-target observation",
                    "critical",
                    "192.0.2.99",
                    443,
                    "https",
                    ["CVE-2024-99999"],
                    'e'),
            ]);

        var report = Verify(
            Nmap([Endpoint("192.0.2.10", 443)]),
            Snapshot([]),
            [supplemental]);

        var targetFinding = Assert.Single(report.TargetFindings);
        Assert.Equal("finding:nuclei_jsonl:host-observation", targetFinding.FindingGroupId);
        Assert.Equal(FindingCorrelation.ScannerOnly, targetFinding.Correlation);
        Assert.DoesNotContain(
            report.Endpoints.SelectMany(static endpoint => endpoint.Findings).Concat(report.TargetFindings),
            static finding => finding.AdvisoryIds.Contains("CVE-2024-99999", StringComparer.Ordinal));
        Assert.Contains(report.Diagnostics, static diagnostic =>
            diagnostic.Code == "verify_out_of_target_evidence_ignored");
    }

    [Fact]
    public void Verify_KeepsSelectedTargetFindingWhenItsPortWasAbsentFromNmap()
    {
        var supplemental = Supplemental(
            "nessus_xml",
            [Finding(
                "nessus_xml",
                "54321",
                "Finding on a differently scoped port",
                "high",
                "192.0.2.10",
                8443,
                "tcp",
                ["CVE-2026-54321"],
                'e')]);

        var report = Verify(
            Nmap([Endpoint("192.0.2.10", 443)]),
            Snapshot([]),
            [supplemental]);

        var finding = Assert.Single(report.TargetFindings);
        Assert.Equal("cve:CVE-2026-54321", finding.FindingGroupId);
        Assert.Contains(report.Diagnostics, static diagnostic =>
            diagnostic.Code == "verify_finding_endpoint_not_in_nmap");
    }

    [Fact]
    public void Verify_AmbiguousHostnameDoesNotAssociateSupplementalFindingToSelectedIp()
    {
        var nmap = Nmap(
            [
                Endpoint("192.0.2.10", 443, hostname: "shared.example"),
                Endpoint("192.0.2.11", 443, hostname: "shared.example"),
            ]);
        var supplemental = Supplemental(
            "nuclei_jsonl",
            [Finding(
                "nuclei_jsonl",
                "shared-host-finding",
                "Ambiguous hostname finding",
                "high",
                "https://shared.example:443",
                443,
                "https",
                ["CVE-2026-11111"],
                'f')]);

        var report = Verify(nmap, Snapshot([]), [supplemental]);

        Assert.Empty(Assert.Single(report.Endpoints).Findings);
        Assert.Empty(report.TargetFindings);
        Assert.Contains(report.Diagnostics, static diagnostic =>
            diagnostic.Code == "verify_hostname_alias_not_asserted");
        Assert.Contains(report.Diagnostics, static diagnostic =>
            diagnostic.Code == "verify_out_of_target_evidence_ignored");
    }

    [Fact]
    public void Verify_ProtocolUnknownFindingIsTargetLevelInsteadOfDuplicatedAcrossTcpAndUdp()
    {
        var supplemental = Supplemental(
            "nessus_xml",
            [Finding(
                "nessus_xml",
                "protocol-unknown",
                "Protocol-unknown finding",
                "medium",
                "192.0.2.10",
                53,
                null,
                ["CVE-2026-22222"],
                'a')]);

        var report = Verify(
            Nmap(
            [
                Endpoint("192.0.2.10", 53, protocol: "tcp"),
                Endpoint("192.0.2.10", 53, protocol: "udp"),
            ]),
            Snapshot([]),
            [supplemental]);

        Assert.All(report.Endpoints, static endpoint => Assert.Empty(endpoint.Findings));
        Assert.Equal("cve:CVE-2026-22222", Assert.Single(report.TargetFindings).FindingGroupId);
        Assert.Contains(report.Diagnostics, static diagnostic =>
            diagnostic.Code == "verify_finding_protocol_unresolved");
    }

    [Fact]
    public void Verify_ConflictingFindingPortIsQuarantinedAndIncomplete()
    {
        var supplemental = Supplemental(
            "nuclei_jsonl",
            [Finding(
                "nuclei_jsonl",
                "conflicting-port",
                "Conflicting port evidence",
                "high",
                "https://192.0.2.10:8443",
                443,
                "https",
                ["CVE-2026-66666"],
                'e')]);

        var report = Verify(
            Nmap([Endpoint("192.0.2.10", 443)]),
            Snapshot([Listener(443, BindScope.Wildcard, IpFamily.Ipv4, "0.0.0.0", "web.exe")]),
            [supplemental]);

        Assert.Empty(Assert.Single(report.Endpoints).Findings);
        Assert.Equal("cve:CVE-2026-66666", Assert.Single(report.TargetFindings).FindingGroupId);
        Assert.Contains(report.Diagnostics, static diagnostic =>
            diagnostic.Code == "verify_finding_endpoint_conflict");
        Assert.False(report.Summary.IsComplete);
        Assert.Equal(ExposureCorrelation.Inconclusive, Assert.Single(report.Endpoints).Correlation);
    }

    [Fact]
    public void Verify_ConflictingFindingTransportIsQuarantinedAndIncomplete()
    {
        var supplemental = Supplemental(
            "nuclei_jsonl",
            [Finding(
                "nuclei_jsonl",
                "conflicting-transport",
                "Conflicting transport evidence",
                "high",
                "https://192.0.2.10:53",
                53,
                "udp",
                ["CVE-2026-77777"],
                'f')]);

        var report = Verify(
            Nmap([Endpoint("192.0.2.10", 53, protocol: "udp")]),
            Snapshot([Listener(
                53,
                BindScope.Wildcard,
                IpFamily.Ipv4,
                "0.0.0.0",
                "dns.exe",
                TransportProtocol.Udp)]),
            [supplemental]);

        Assert.Empty(Assert.Single(report.Endpoints).Findings);
        Assert.Equal("cve:CVE-2026-77777", Assert.Single(report.TargetFindings).FindingGroupId);
        Assert.Contains(report.Diagnostics, static diagnostic =>
            diagnostic.Code == "verify_finding_endpoint_conflict");
        Assert.False(report.Summary.IsComplete);
    }

    [Fact]
    public void Verify_HostnameSelectedFindingNeverClaimsExactOwnerCorroboration()
    {
        var nmap = Nmap([Endpoint("192.0.2.10", 443, hostname: "web.example")]);
        var supplemental = Supplemental(
            "nuclei_jsonl",
            [Finding(
                "nuclei_jsonl",
                "hostname-finding",
                "Hostname finding",
                "high",
                "https://web.example:443",
                443,
                "https",
                ["CVE-2026-33333"],
                'b')]);
        var snapshot = Snapshot(
            [Listener(443, BindScope.Wildcard, IpFamily.Ipv4, "0.0.0.0", "web.exe")]);

        var report = new ExposureVerificationService().Verify(
            "test-version",
            "web.example",
            "internet-edge",
            nmap,
            [supplemental],
            snapshot,
            NoMappings,
            firewallRequested: true);

        var finding = Assert.Single(Assert.Single(report.Endpoints).Findings);
        Assert.Equal(FindingCorrelation.OwnerAmbiguous, finding.Correlation);
    }

    [Fact]
    public void Verify_DefaultRedactionRemovesEquivalentIpv6FindingAlias()
    {
        const string expandedAddress = "2001:0DB8:0000:0000:0000:0000:0000:0001";
        var nmap = Nmap([Endpoint("2001:db8::1", 443)]);
        var supplemental = Supplemental(
            "nuclei_jsonl",
            [Finding(
                "nuclei_jsonl",
                $"template-{expandedAddress}",
                $"Finding for {expandedAddress}",
                "high",
                $"https://[{expandedAddress}]:443",
                443,
                "https",
                ["CVE-2026-44444"],
                'c')]);

        var report = new ExposureVerificationService().Verify(
            "test-version",
            "2001:db8::1",
            "internet-edge",
            nmap,
            [supplemental],
            Snapshot([]),
            NoMappings,
            firewallRequested: true);
        var json = JsonOutput.Serialize(ExposureVerificationRedactor.Redact(report));

        Assert.DoesNotContain(expandedAddress, json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_DefaultRedactionRemovesEquivalentIdnFindingAlias()
    {
        const string unicodeHostname = "bücher.example";
        const string asciiHostname = "xn--bcher-kva.example";
        var nmap = Nmap([Endpoint("192.0.2.10", 443, hostname: unicodeHostname)]);
        var supplemental = Supplemental(
            "nuclei_jsonl",
            [Finding(
                "nuclei_jsonl",
                $"template-{asciiHostname}",
                $"Finding for {asciiHostname}",
                "high",
                $"https://{asciiHostname}:443",
                443,
                "https",
                ["CVE-2026-55555"],
                'd')]);

        var report = new ExposureVerificationService().Verify(
            "test-version",
            unicodeHostname,
            "internet-edge",
            nmap,
            [supplemental],
            Snapshot([]),
            NoMappings,
            firewallRequested: true);
        var json = JsonOutput.Serialize(ExposureVerificationRedactor.Redact(report));

        Assert.DoesNotContain(unicodeHostname, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(asciiHostname, json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_DefaultRedactionRemovesUnicodeAliasForAsciiIdnSelection()
    {
        const string unicodeHostname = "bücher.example";
        const string asciiHostname = "xn--bcher-kva.example";
        var nmap = Nmap([Endpoint("192.0.2.10", 443, hostname: asciiHostname)]);
        var supplemental = Supplemental(
            "nuclei_jsonl",
            [Finding(
                "nuclei_jsonl",
                $"template-{unicodeHostname}",
                $"Finding for {unicodeHostname}",
                "high",
                $"https://{unicodeHostname}:443",
                443,
                "https",
                ["CVE-2026-55556"],
                'e')]);

        var report = new ExposureVerificationService().Verify(
            "test-version",
            asciiHostname,
            "internet-edge",
            nmap,
            [supplemental],
            Snapshot([]),
            NoMappings,
            firewallRequested: true);
        var json = JsonOutput.Serialize(ExposureVerificationRedactor.Redact(report));

        Assert.DoesNotContain(unicodeHostname, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(asciiHostname, json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_DefaultRedactionRemovesSupplementalHostnameForSelectedIp()
    {
        const string supplementalHostname = "secret.internal.example";
        var nessus = Document(
            "nessus_xml",
            [Endpoint("192.0.2.10", 443, hostname: supplementalHostname)],
            [Finding(
                "nessus_xml",
                "12345",
                $"TLS service on {supplementalHostname}",
                "high",
                "192.0.2.10",
                443,
                "tcp",
                ["CVE-2026-55557"],
                'f')],
            true,
            "nessus.xml",
            'f');

        var report = Verify(
            Nmap([Endpoint("192.0.2.10", 443)]),
            Snapshot([]),
            [nessus]);
        var json = JsonOutput.Serialize(ExposureVerificationRedactor.Redact(report));

        Assert.DoesNotContain(supplementalHostname, json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_DefaultRedactionRemovesHostAliasFromPortlessNessusFinding()
    {
        const string supplementalHostname = "secret.internal.example";
        var nessus = Supplemental(
            "nessus_xml",
            [Finding(
                "nessus_xml",
                "19506",
                $"Scan information for {supplementalHostname}",
                "info",
                "192.0.2.10",
                null,
                null,
                [],
                'a')]) with
        {
            PrivateHostAliases = [new("192.0.2.10", supplementalHostname)],
        };

        var report = Verify(
            Nmap([Endpoint("192.0.2.10", 443)]),
            Snapshot([]),
            [nessus]);
        var json = JsonOutput.Serialize(ExposureVerificationRedactor.Redact(report));

        Assert.DoesNotContain(supplementalHostname, json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_DefaultRedactionUsesHostAliasForHostnameSelection()
    {
        const string selectedHostname = "web.example";
        const string supplementalHostname = "secret.internal.example";
        var nessus = Supplemental(
            "nessus_xml",
            [Finding(
                "nessus_xml",
                "19506",
                $"Scan information for {supplementalHostname}",
                "info",
                selectedHostname,
                null,
                null,
                [],
                'b')]) with
        {
            PrivateHostAliases = [new(selectedHostname, supplementalHostname)],
        };
        var report = new ExposureVerificationService().Verify(
            "test-version",
            selectedHostname,
            "internet-edge",
            Nmap([Endpoint("192.0.2.10", 443, hostname: selectedHostname)]),
            [nessus],
            Snapshot([]),
            NoMappings,
            firewallRequested: true);
        var json = JsonOutput.Serialize(ExposureVerificationRedactor.Redact(report));

        Assert.DoesNotContain(supplementalHostname, json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_ManySameHostUrlsKeepRedactionAliasesBounded()
    {
        var findings = Enumerable.Range(0, 1_000)
            .Select(index => Finding(
                "nuclei_jsonl",
                $"template-{index}",
                $"Finding {index}",
                "medium",
                $"https://192.0.2.10:443/path/{index}",
                443,
                "https",
                [],
                (char)('a' + index % 6)))
            .ToArray();

        var report = Verify(
            Nmap([Endpoint("192.0.2.10", 443)]),
            Snapshot([]),
            [Supplemental("nuclei_jsonl", findings)]);
        var started = System.Diagnostics.Stopwatch.StartNew();
        _ = JsonOutput.Serialize(ExposureVerificationRedactor.Redact(report));
        started.Stop();

        Assert.InRange(report.PrivateRedactionAliases.Count, 1, 32);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(5), $"Redaction took {started.Elapsed}.");
    }

    [Fact]
    public void Verify_EndpointAndFindingOrderingIsDeterministic()
    {
        var nmap = Nmap(
            [
                Endpoint("192.0.2.10", 8443),
                Endpoint("192.0.2.10", 22),
                Endpoint("192.0.2.10", 443),
            ],
            [
                Finding("nmap_nse", "z-check", "Z check", "low", "192.0.2.10", 443, "tcp", [], 'f'),
                Finding("nmap_nse", "a-check", "A check", "high", "192.0.2.10", 443, "tcp", [], 'a'),
                Finding("nmap_nse", "cve-z", "CVE Z", "medium", "192.0.2.10", 443, "tcp", ["CVE-2025-9999"], '9'),
                Finding("nmap_nse", "cve-a", "CVE A", "medium", "192.0.2.10", 443, "tcp", ["CVE-2024-1111"], '1'),
            ]);

        var report = Verify(nmap, Snapshot([]));

        Assert.Equal([22, 443, 8443], report.Endpoints.Select(static endpoint => endpoint.ExternalPort));
        Assert.Equal(
            [
                "cve:CVE-2024-1111",
                "cve:CVE-2025-9999",
                "finding:nmap_nse:a-check",
                "finding:nmap_nse:z-check",
            ],
            Find(report, "tcp", 443).Findings.Select(static finding => finding.FindingGroupId));
    }

    private static ExposureVerificationReport Verify(
        PentestImportDocument nmap,
        SystemSnapshot snapshot,
        IReadOnlyList<PentestImportDocument>? supplemental = null,
        IReadOnlyDictionary<VerificationEndpointKey, VerificationEndpointKey>? mappings = null) =>
        new ExposureVerificationService().Verify(
            "test-version",
            "192.0.2.10",
            "internet-edge",
            nmap,
            supplemental ?? [],
            snapshot,
            mappings ?? NoMappings,
            firewallRequested: true);

    private static VerifiedExposureEndpoint Find(
        ExposureVerificationReport report,
        string protocol,
        int externalPort) => Assert.Single(report.Endpoints, endpoint =>
            endpoint.Protocol == protocol && endpoint.ExternalPort == externalPort);

    private static PentestImportDocument Nmap(
        IReadOnlyList<ImportedEndpoint> endpoints,
        IReadOnlyList<ImportedFinding>? findings = null,
        bool isComplete = true) => Document("nmap_xml", endpoints, findings ?? [], isComplete, "nmap.xml", 'a');

    private static PentestImportDocument Supplemental(
        string source,
        IReadOnlyList<ImportedFinding> findings,
        bool isComplete = true) => Document(
            source,
            [],
            findings,
            isComplete,
            source == "nessus_xml" ? "nessus.xml" : "nuclei.jsonl",
            source == "nessus_xml" ? 'c' : 'b');

    private static PentestImportDocument Document(
        string source,
        IReadOnlyList<ImportedEndpoint> endpoints,
        IReadOnlyList<ImportedFinding> findings,
        bool isComplete,
        string fileName,
        char hashCharacter) => new(
            PentestImportDocument.CurrentSchemaVersion,
            "import-test",
            DateTimeOffset.UnixEpoch,
            new(fileName, 123, new string(hashCharacter, 64)),
            source,
            "fixture",
            isComplete,
            endpoints,
            findings,
            isComplete ? [] : [new("fixture_incomplete", "Fixture evidence is incomplete.")]);

    private static ImportedEndpoint Endpoint(
        string target,
        int port,
        string? hostname = null,
        string protocol = "tcp",
        string state = "open") => new(
            target,
            hostname,
            protocol,
            port,
            state,
            state == "open" ? "syn-ack" : "fixture-state",
            new(
                protocol == "tcp" ? "https" : "domain",
                null,
                null,
                null,
                [],
                ImportedEvidenceStrength.Strong,
                "fixture_probe"));

    private static ImportedFinding Finding(
        string source,
        string findingId,
        string title,
        string severity,
        string target,
        int? port,
        string? protocol,
        IReadOnlyList<string> advisoryIds,
        char hashCharacter) => new(
            source,
            findingId,
            title,
            severity,
            target,
            port,
            protocol,
            ImportedClaimStatus.ImportedMatch,
            ImportedEvidenceStrength.Unresolved,
            advisoryIds,
            [],
            new string(hashCharacter, 64),
            findingId,
            null);

    private static SystemSnapshot Snapshot(
        IReadOnlyList<ListenerEvidence> listeners,
        CollectorStatus ownerStatus = CollectorStatus.Complete) => new(
            SystemSnapshot.CurrentSchemaVersion,
            "snapshot-test",
            DateTimeOffset.UnixEpoch.AddMinutes(1),
            5,
            "Windows",
            [
                Collector("sockets", CollectorStatus.Complete),
                Collector("process_owners", ownerStatus),
                Collector("interfaces", CollectorStatus.Complete),
                Collector("windows_firewall", CollectorStatus.Complete),
                Collector("docker", CollectorStatus.Unavailable),
            ],
            [],
            listeners,
            []);

    private static CollectorReport Collector(string name, CollectorStatus status) => new(
        name,
        status,
        DateTimeOffset.UnixEpoch,
        1,
        []);

    private static ListenerEvidence Listener(
        int port,
        BindScope scope,
        IpFamily family,
        string address,
        string imageName,
        TransportProtocol protocol = TransportProtocol.Tcp)
    {
        var owner = new OwnerEvidence(
            1234,
            DateTimeOffset.UnixEpoch,
            imageName,
            $"C:\\Apps\\{imageName}",
            new string('1', 64),
            4,
            "System",
            "S-1-5-18",
            "NT AUTHORITY\\SYSTEM",
            ["FixtureService"],
            false,
            true,
            []);
        return new(
            $"{protocol.ToString().ToLowerInvariant()}/{family.ToString().ToLowerInvariant()}/{address}/{port}",
            protocol,
            family,
            address,
            port,
            protocol == TransportProtocol.Tcp ? "LISTEN" : "BOUND",
            scope,
            scope.ToString(),
            owner,
            [],
            new(
                FirewallVerdict.Allow,
                Confidence.Medium,
                "Fixture policy allows the endpoint.",
                [],
                []),
            ["Fixture native socket evidence."],
            [],
            []);
    }
}
