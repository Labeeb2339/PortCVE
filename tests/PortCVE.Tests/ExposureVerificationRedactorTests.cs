using PortCVE.Domain;
using PortCVE.Output;
using PortCVE.Remote.Imports;
using PortCVE.Snapshots;
using PortCVE.Verification;

namespace PortCVE.Tests;

public sealed class ExposureVerificationRedactorTests
{
    [Fact]
    public void Redact_RemovesSelectedHostnameWhenClosedEndpointsWereOmitted()
    {
        const string hostname = "secret-host.internal.example";
        var report = Report(
            "192.0.2.10",
            "10.20.30.40",
            "closed",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "diagnostic",
            "listener limitation",
            "correlation limitation") with
        {
            Endpoints = [],
            TargetFindings =
            [
                new(
                    $"finding:nuclei:{hostname}",
                    $"Finding for {hostname}",
                    "high",
                    [],
                    FindingCorrelation.ScannerOnly,
                    "not_assessed",
                    [
                        new(
                            "nuclei_jsonl",
                            $"template-{hostname}",
                            $"Finding for {hostname}",
                            "high",
                            ImportedClaimStatus.ImportedMatch,
                            ImportedEvidenceStrength.Unresolved,
                            [],
                            new string('d', 64),
                            $"matcher-{hostname}"),
                    ]),
            ],
            PrivateRedactionAliases = [hostname],
        };

        var json = JsonOutput.Serialize(ExposureVerificationRedactor.Redact(report));

        Assert.DoesNotContain(hostname, json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Redact_ShortTargetAliasDoesNotModifyStructuredCveIdentity()
    {
        var report = Report(
            "cve",
            "10.20.30.40",
            "open",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "diagnostic",
            "listener limitation",
            "correlation limitation") with
        {
            PrivateRedactionAliases = ["cve"],
        };

        var finding = Assert.Single(ExposureVerificationRedactor.Redact(report).Endpoints[0].Findings);

        Assert.Equal("cve:CVE-2024-12345", finding.FindingGroupId);
        Assert.Equal(["CVE-2024-12345"], finding.AdvisoryIds);
        Assert.Equal(["CVE-2024-12345"], Assert.Single(finding.Observations).AdvisoryIds);
    }

    [Fact]
    public void Redact_RemovesTargetAddressOwnerAndDiagnosticDetailsConsistently()
    {
        const string target = "private-target.example";
        const string address = "10.20.30.40";
        const string stateReason = "private-state-reason";
        const string ownerDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const string containerIdentity = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const string diagnosticMessage = "private diagnostic mentioning 10.20.30.40";
        const string listenerLimitation = "private listener limitation";
        const string correlationLimitation = "private correlation limitation";
        var report = Report(
            target,
            address,
            stateReason,
            ownerDigest,
            containerIdentity,
            diagnosticMessage,
            listenerLimitation,
            correlationLimitation);
        var endpoint = report.Endpoints[0];
        var finding = endpoint.Findings[0];
        report = report with
        {
            Endpoints =
            [
                endpoint with
                {
                    OutsideObservations =
                    [
                        endpoint.OutsideObservations[0] with
                        {
                            Service = endpoint.OutsideObservations[0].Service! with
                            {
                                ExtraInfo = $"banner for {target} via {address}",
                            },
                        },
                    ],
                    LocalListeners =
                    [
                        endpoint.LocalListeners[0] with
                        {
                            ImageName = $"owner-{target}.exe",
                            Services = [$"service-{address}"],
                        },
                    ],
                    Findings =
                    [
                        finding with
                        {
                            Title = $"finding for {target}",
                            Observations =
                            [
                                finding.Observations[0] with
                                {
                                    FindingId = $"template-{address}",
                                    Title = $"finding for {target}",
                                    Matcher = $"matcher-{address}",
                                },
                            ],
                        },
                    ],
                },
            ],
            TargetFindings =
            [
                finding with
                {
                    FindingGroupId = $"finding:nuclei:{target}",
                    Title = $"target observation for {address}",
                },
            ],
        };

        var redacted = ExposureVerificationRedactor.Redact(report);
        var json = JsonOutput.Serialize(redacted);

        Assert.Equal(VerificationPrivacyMode.Reduced, redacted.PrivacyMode);
        Assert.Equal("target-1", redacted.Association.ImportedTarget);
        Assert.Equal("operator-labeled-vantage", redacted.Association.Vantage);
        Assert.Equal("nmapxml-input", redacted.Inputs[0].FileName);
        Assert.Equal(new string('0', 64), redacted.Inputs[0].Sha256);
        Assert.Equal("target-1", redacted.Endpoints[0].OutsideObservations[0].Target);
        Assert.Null(redacted.Endpoints[0].OutsideObservations[0].Hostname);
        Assert.Equal("redacted", redacted.Endpoints[0].OutsideObservations[0].StateReason);
        Assert.Equal("sha256:redacted", redacted.Endpoints[0].LocalListeners[0].OwnerIdentity);
        Assert.Equal(["redacted image identity"], redacted.Endpoints[0].LocalListeners[0].ContainerImages);
        Assert.Equal(["Listener limitation details were redacted."], redacted.Endpoints[0].LocalListeners[0].Limitations);
        Assert.Equal(
            ["Correlation limitations are present; rerun with --include-private for details."],
            redacted.Endpoints[0].Limitations);
        Assert.Equal("fixture_diagnostic", redacted.Diagnostics[0].Code);
        Assert.Equal(
            "Diagnostic details redacted; rerun with --include-private to inspect them locally.",
            redacted.Diagnostics[0].Message);

        Assert.DoesNotContain(target, json, StringComparison.Ordinal);
        Assert.DoesNotContain(address, json, StringComparison.Ordinal);
        Assert.DoesNotContain(stateReason, json, StringComparison.Ordinal);
        Assert.DoesNotContain(ownerDigest, json, StringComparison.Ordinal);
        Assert.DoesNotContain(containerIdentity, json, StringComparison.Ordinal);
        Assert.DoesNotContain(diagnosticMessage, json, StringComparison.Ordinal);
        Assert.DoesNotContain(listenerLimitation, json, StringComparison.Ordinal);
        Assert.DoesNotContain(correlationLimitation, json, StringComparison.Ordinal);
        Assert.DoesNotContain("private-nmap.xml", json, StringComparison.Ordinal);
        Assert.DoesNotContain("private-vantage", json, StringComparison.Ordinal);

        Assert.Equal(target, report.Association.ImportedTarget);
        Assert.Equal(address, report.Endpoints[0].LocalListeners[0].LocalAddress);
        Assert.Equal(diagnosticMessage, report.Diagnostics[0].Message);
    }

    [Fact]
    public void Redact_NormalizesAddressesByBindScopeAndPreservesSafeOwnerKinds()
    {
        var report = Report(
            "private-target.example",
            "10.20.30.40",
            "syn-ack",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "example/private:1",
            "diagnostic",
            "limitation",
            "correlation limitation");
        var endpoint = report.Endpoints[0];
        report = report with
        {
            Endpoints =
            [
                endpoint with
                {
                    LocalListeners =
                    [
                        endpoint.LocalListeners[0],
                        endpoint.LocalListeners[0] with
                        {
                            BindScope = BindScope.Loopback,
                            LocalAddress = "127.0.0.1",
                            OwnerIdentity = "process:loopback.exe",
                            OwnerIdentityStrength = OwnerIdentityStrength.NameOnly,
                            ContainerImages = [],
                        },
                        endpoint.LocalListeners[0] with
                        {
                            BindScope = BindScope.Wildcard,
                            LocalAddress = "0.0.0.0",
                            OwnerIdentity = "service:web",
                            OwnerIdentityStrength = OwnerIdentityStrength.Service,
                            ContainerImages = [],
                        },
                        endpoint.LocalListeners[0] with
                        {
                            BindScope = BindScope.Unknown,
                            LocalAddress = "fe80::1%7",
                            OwnerIdentity = "unknown",
                            OwnerIdentityStrength = OwnerIdentityStrength.Unknown,
                            ContainerImages = [],
                        },
                    ],
                },
            ],
        };

        var listeners = Assert.Single(ExposureVerificationRedactor.Redact(report).Endpoints).LocalListeners;

        Assert.Equal(["interface", "loopback", "any", "unknown"],
            listeners.Select(static listener => listener.LocalAddress));
        Assert.Equal("sha256:redacted", listeners[0].OwnerIdentity);
        Assert.Equal("process:loopback.exe", listeners[1].OwnerIdentity);
        Assert.Equal("service:web", listeners[2].OwnerIdentity);
        Assert.Equal("unknown", listeners[3].OwnerIdentity);
    }

    [Fact]
    public void Redact_IsIdempotentAndKeepsCorrelationProvenance()
    {
        var report = Report(
            "private-target.example",
            "10.20.30.40",
            "syn-ack",
            "container-image-set:private-digest",
            "example/private:1",
            "diagnostic",
            "limitation",
            "correlation limitation");

        var once = ExposureVerificationRedactor.Redact(report);
        var twice = ExposureVerificationRedactor.Redact(once);

        Assert.Equal(VerificationPrivacyMode.Reduced, once.PrivacyMode);
        Assert.Equal(JsonOutput.Serialize(once), JsonOutput.Serialize(twice));
        var finding = Assert.Single(Assert.Single(once.Endpoints).Findings);
        var observation = Assert.Single(finding.Observations);
        Assert.Equal("cve:CVE-2024-12345", finding.FindingGroupId);
        Assert.Equal("nuclei_jsonl", observation.Source);
        Assert.Equal(new string('0', 64), observation.SourceRecordSha256);
        Assert.Equal("not_assessed", finding.Exploitability);
        Assert.Equal(443, Assert.Single(once.Association.PortMappings).ExternalPort);
    }

    private static ExposureVerificationReport Report(
        string target,
        string address,
        string stateReason,
        string ownerIdentity,
        string containerIdentity,
        string diagnosticMessage,
        string listenerLimitation,
        string correlationLimitation)
    {
        var findingObservation = new VerificationFindingObservation(
            "nuclei_jsonl",
            "tls-template",
            "TLS finding",
            "high",
            ImportedClaimStatus.ImportedMatch,
            ImportedEvidenceStrength.Unresolved,
            ["CVE-2024-12345"],
            new string('c', 64),
            "tls-matcher");
        var finding = new VerificationFindingGroup(
            "cve:CVE-2024-12345",
            "TLS finding",
            "high",
            ["CVE-2024-12345"],
            FindingCorrelation.OwnerCorroborated,
            "not_assessed",
            [findingObservation]);
        var listener = new VerificationLocalListener(
            IpFamily.Ipv4,
            BindScope.Interface,
            address,
            8443,
            ownerIdentity,
            ownerIdentity.StartsWith("container-image-set:", StringComparison.Ordinal)
                ? OwnerIdentityStrength.ContainerImage
                : OwnerIdentityStrength.Sha256,
            "server.exe",
            ["WebService"],
            [containerIdentity],
            FirewallVerdict.Allow,
            Confidence.Medium,
            [listenerLimitation]);
        var endpoint = new VerifiedExposureEndpoint(
            "tcp",
            443,
            8443,
            ExposureCorrelation.CorrelatedOpen,
            [
                new(
                    "nmap_xml",
                    target,
                    target,
                    "open",
                    stateReason,
                    new(
                        "https",
                        "Fixture HTTP Server",
                        "1.0",
                        null,
                        [],
                        ImportedEvidenceStrength.Strong,
                        "nmap_service_probe")),
            ],
            [listener],
            [finding],
            [correlationLimitation]);
        return new(
            ExposureVerificationReport.CurrentSchemaVersion,
            "test-version",
            VerificationPrivacyMode.Private,
            DateTimeOffset.UnixEpoch,
            new(
                target,
                true,
                "private-vantage",
                [new("tcp", 443, 8443)]),
            [
                new(
                    VerificationInputKind.NmapXml,
                    "private-nmap.xml",
                    123,
                    new string('a', 64),
                    "7.98",
                    true,
                    DateTimeOffset.UnixEpoch),
                new(
                    VerificationInputKind.LiveWindows,
                    null,
                    null,
                    null,
                    "test-version",
                    true,
                    DateTimeOffset.UnixEpoch),
            ],
            [endpoint],
            [],
            new(1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, true),
            [new("fixture_diagnostic", diagnosticMessage)],
            "Fixture claim boundary.");
    }
}
