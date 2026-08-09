using PortCVE.Output;
using PortCVE.Remote;
using PortCVE.Remote.Advisories;

namespace PortCVE.Tests;

public sealed class RemoteAuditServiceTests
{
    [Fact]
    public async Task AssessAsync_DeduplicatesVerifiedIdentityQueriesAcrossTargets()
    {
        var scanner = new FixedHostScanner(RemoteProductConfidence.BannerPattern);
        var advisory = new FixedAdvisoryClient(new(
            RemoteAdvisoryStatus.Complete,
            RemoteAdvisoryResult.ProviderName,
            RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
            DateTimeOffset.UnixEpoch,
            [],
            []));
        var service = new RemoteAuditService(scanner, advisory);

        var report = await service.AssessAsync(
            Options(["192.0.2.10", "192.0.2.11"], online: true),
            CancellationToken.None);

        Assert.Equal(1, advisory.CallCount);
        Assert.Equal(2, report.AdvisoryAssessments.Count);
        var providerResult = Assert.Single(report.AdvisoryResults);
        Assert.Equal(RemoteAdvisoryStatus.Complete, providerResult.Status);
        Assert.All(report.AdvisoryAssessments, static item =>
        {
            Assert.Equal(RemoteIdentityDisposition.Resolved, item.IdentityDisposition);
            Assert.Equal("remote-advisory-result-0001", item.AdvisoryResultId);
            Assert.StartsWith("cpe:2.3:a:openbsd:openssh:9.6:p1:", item.Cpe23Uri, StringComparison.Ordinal);
        });
        Assert.Equal(RemoteAdvisoryStatus.Complete, report.AdvisoryStatus);
        Assert.True(report.Summary.IsComplete);
    }

    [Fact]
    public async Task AssessAsync_RepeatedIdentitySerializesProviderMatchesOnceAndKeepsEndpointReferences()
    {
        var targets = Enumerable.Range(0, 200)
            .Select(index => $"host-{index:000}.example")
            .ToArray();
        var advisory = new FixedAdvisoryClient(CompleteAdvisoryResultWithMatch());
        var service = new RemoteAuditService(
            new FixedHostScanner(RemoteProductConfidence.BannerPattern),
            advisory);

        var report = await service.AssessAsync(
            Options(targets, online: true),
            CancellationToken.None);

        Assert.Equal(1, advisory.CallCount);
        Assert.Equal(200, report.AdvisoryAssessments.Count);
        Assert.Single(report.AdvisoryResults);
        Assert.All(report.AdvisoryAssessments, static assessment =>
            Assert.Equal("remote-advisory-result-0001", assessment.AdvisoryResultId));
        Assert.Equal(1, report.Summary.AdvisoryResultCount);
        Assert.Equal(1, report.Summary.AdvisoryMatchCount);

        var privateJson = JsonOutput.Serialize(report);
        var redactedJson = JsonOutput.Serialize(RemoteAuditRedactor.Redact(report));
        Assert.Equal(1, CountOccurrences(privateJson, "CVE-2026-42424"));
        Assert.Equal(1, CountOccurrences(redactedJson, "CVE-2026-42424"));
        Assert.Contains("host-000.example", privateJson, StringComparison.Ordinal);
        Assert.DoesNotContain("host-000.example", redactedJson, StringComparison.Ordinal);
        Assert.Contains("SSH-2.0-OpenSSH_9.6p1", privateJson, StringComparison.Ordinal);
        Assert.DoesNotContain("SSH-2.0-OpenSSH_9.6p1", redactedJson, StringComparison.Ordinal);

        using var textOutput = new StringWriter();
        using var textError = new StringWriter();
        RemoteAuditTextRenderer.Render(report, textOutput, textError);
        Assert.Equal(1, CountOccurrences(textOutput.ToString(), "CVE-2026-42424"));
        Assert.Contains("200 endpoint association(s)", textOutput.ToString(), StringComparison.Ordinal);
        Assert.Contains("(+195 more)", textOutput.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AssessAsync_DistinctIdentityCapStopsNvdAndMarksReportPartial()
    {
        const int identitiesBeyondLimit = 60;
        var targetCount = RemoteAuditService.MaximumUniqueAdvisoryIdentities + identitiesBeyondLimit;
        var targets = Enumerable.Range(0, targetCount)
            .Select(index => $"identity-{index:000}.example")
            .ToArray();
        var advisory = new FixedAdvisoryClient(new(
            RemoteAdvisoryStatus.Complete,
            RemoteAdvisoryResult.ProviderName,
            RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
            DateTimeOffset.UnixEpoch,
            [],
            []));
        var service = new RemoteAuditService(new DistinctIdentityHostScanner(), advisory);

        var report = await service.AssessAsync(
            Options(targets, online: true),
            CancellationToken.None);

        Assert.Equal(RemoteAuditService.MaximumUniqueAdvisoryIdentities, advisory.CallCount);
        Assert.Equal(RemoteAuditService.MaximumUniqueAdvisoryIdentities, report.AdvisoryResults.Count);
        Assert.Equal(RemoteAuditService.MaximumUniqueAdvisoryIdentities, report.Summary.AdvisoryResultCount);
        Assert.Equal(RemoteAdvisoryStatus.Partial, report.AdvisoryStatus);
        Assert.False(report.Summary.IsComplete);
        Assert.Equal(identitiesBeyondLimit, report.AdvisoryAssessments.Count(static assessment =>
            assessment.AdvisoryResultId is null &&
            assessment.Diagnostics.Any(static diagnostic =>
                diagnostic.Code == "nvd_identity_cap_exceeded")));
        Assert.Contains(report.Diagnostics, static diagnostic =>
            diagnostic.Code == "remote_advisory_identity_limit_exceeded");

        using var textOutput = new StringWriter();
        using var textError = new StringWriter();
        RemoteAuditTextRenderer.Render(report, textOutput, textError);
        Assert.Equal(50, CountOccurrences(textError.ToString(), "nvd_identity_cap_exceeded:"));
        Assert.Contains(
            "remote_assessment_diagnostics_truncated: 10 additional",
            textError.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task AssessAsync_HeaderReportedIdentityNeverCallsNvdAndStrictEvidenceIsIncomplete()
    {
        var scanner = new FixedHostScanner(RemoteProductConfidence.HeaderReported);
        var advisory = new FixedAdvisoryClient(new(
            RemoteAdvisoryStatus.Complete,
            RemoteAdvisoryResult.ProviderName,
            RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
            DateTimeOffset.UnixEpoch,
            [],
            []));
        var service = new RemoteAuditService(scanner, advisory);

        var report = await service.AssessAsync(
            Options(["192.0.2.10"], online: true),
            CancellationToken.None);

        Assert.Equal(0, advisory.CallCount);
        var assessment = Assert.Single(report.AdvisoryAssessments);
        Assert.Equal(RemoteIdentityDisposition.NotEligible, assessment.IdentityDisposition);
        Assert.Null(assessment.AdvisoryResultId);
        Assert.Empty(report.AdvisoryResults);
        Assert.Equal(RemoteAdvisoryStatus.Partial, report.AdvisoryStatus);
        Assert.False(report.Summary.IsComplete);
    }

    [Theory]
    [InlineData("timed_out")]
    [InlineData("unreachable")]
    public async Task AssessAsync_InconclusiveEndpointStateIsIncomplete(string stateName)
    {
        var state = stateName switch
        {
            "timed_out" => RemotePortState.TimedOut,
            "unreachable" => RemotePortState.Unreachable,
            _ => throw new ArgumentOutOfRangeException(nameof(stateName)),
        };
        var advisory = new FixedAdvisoryClient(new(
            RemoteAdvisoryStatus.Complete,
            RemoteAdvisoryResult.ProviderName,
            RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
            DateTimeOffset.UnixEpoch,
            [],
            []));
        var service = new RemoteAuditService(new FixedPortStateHostScanner(state), advisory);

        var report = await service.AssessAsync(
            Options(["192.0.2.10"], online: true),
            CancellationToken.None);

        Assert.Equal(0, advisory.CallCount);
        Assert.False(report.Summary.IsComplete);
        Assert.Contains(report.Diagnostics, static diagnostic =>
            diagnostic.Code == "remote_endpoints_incomplete");
    }

    [Fact]
    public async Task Redact_RemovesTargetAddressAndRawBannerButRetainsProductAndPort()
    {
        var advisory = new FixedAdvisoryClient(new(
                RemoteAdvisoryStatus.NotRequested,
                RemoteAdvisoryResult.ProviderName,
                RemoteAdvisoryResult.OfflineNetworkMode,
                null,
                [],
                []));
        var service = new RemoteAuditService(
            new FixedHostScanner(RemoteProductConfidence.BannerPattern),
            advisory);
        var report = await service.AssessAsync(
            Options(["private.example"], online: false),
            CancellationToken.None);

        var json = JsonOutput.Serialize(RemoteAuditRedactor.Redact(report));

        Assert.DoesNotContain("private.example", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SSH-2.0-OpenSSH_9.6p1", json, StringComparison.Ordinal);
        Assert.Contains("target-001", json, StringComparison.Ordinal);
        Assert.Contains("OpenSSH", json, StringComparison.Ordinal);
        Assert.Contains("\"port\": 22", json, StringComparison.Ordinal);
        Assert.Equal(0, advisory.CallCount);
    }

    [Fact]
    public async Task Redact_ReplacesDiagnosticMessagesAndDropsRemoteControlledAllowAttribute()
    {
        var advisory = new FixedAdvisoryClient(new(
            RemoteAdvisoryStatus.Unavailable,
            RemoteAdvisoryResult.ProviderName,
            RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
            null,
            [],
            [new(
                "nvd_fixture_error",
                "NVD lookup mentioned 203.0.113.77 and secret-advisory-detail.")]));
        var service = new RemoteAuditService(new LeakyDiagnosticHostScanner(), advisory);
        var report = await service.AssessAsync(
            Options(["private.example"], online: true),
            CancellationToken.None);
        report = report with
        {
            AdvisoryAssessments = report.AdvisoryAssessments.Select(assessment => assessment with
            {
                Diagnostics =
                [
                    .. assessment.Diagnostics,
                    new(
                        "assessment_fixture_error",
                        "Assessment mentioned private.example and secret-assessment-detail."),
                ],
            }).ToArray(),
            Diagnostics =
            [
                .. report.Diagnostics,
                new(
                    "report_fixture_error",
                    "Report mentioned 203.0.113.77 and secret-report-detail."),
            ],
        };

        var privateJson = JsonOutput.Serialize(report);
        var redactedJson = JsonOutput.Serialize(RemoteAuditRedactor.Redact(report));

        Assert.Contains("secret-host-detail", privateJson, StringComparison.Ordinal);
        Assert.Contains("secret-port-detail", privateJson, StringComparison.Ordinal);
        Assert.Contains("secret-advisory-detail", privateJson, StringComparison.Ordinal);
        Assert.Contains("secret-assessment-detail", privateJson, StringComparison.Ordinal);
        Assert.Contains("secret-report-detail", privateJson, StringComparison.Ordinal);
        Assert.Contains("secret-allow-detail", privateJson, StringComparison.Ordinal);
        Assert.DoesNotContain("private.example", redactedJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("203.0.113.77", redactedJson, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-host-detail", redactedJson, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-port-detail", redactedJson, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-advisory-detail", redactedJson, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-assessment-detail", redactedJson, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-report-detail", redactedJson, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-allow-detail", redactedJson, StringComparison.Ordinal);
        Assert.Contains("host_fixture_error", redactedJson, StringComparison.Ordinal);
        Assert.Contains("port_fixture_error", redactedJson, StringComparison.Ordinal);
        Assert.Contains("nvd_fixture_error", redactedJson, StringComparison.Ordinal);
        Assert.Contains("assessment_fixture_error", redactedJson, StringComparison.Ordinal);
        Assert.Contains("report_fixture_error", redactedJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AssessAsync_RejectsPlanThatCannotFitBoundedInMemoryReport()
    {
        var service = new RemoteAuditService(
            new FixedHostScanner(RemoteProductConfidence.BannerPattern),
            new FixedAdvisoryClient(new(
                RemoteAdvisoryStatus.NotRequested,
                RemoteAdvisoryResult.ProviderName,
                RemoteAdvisoryResult.OfflineNetworkMode,
                null,
                [],
                [])));
        var targets = Enumerable.Range(0, 1001)
            .Select(index => $"192.0.{index / 256}.{index % 256}")
            .ToArray();
        var options = Options(targets, online: false) with
        {
            Ports = Enumerable.Range(1, 1000).ToArray(),
        };

        var error = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            service.AssessAsync(options, CancellationToken.None));

        Assert.Contains("1,000,000", error.Message, StringComparison.Ordinal);
    }

    private static RemoteAdvisoryResult CompleteAdvisoryResultWithMatch()
    {
        const string cpe = "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*";
        var applicability = new RemoteAdvisoryApplicability(
            RemoteAdvisoryApplicabilityDisposition.DirectCandidate,
            true,
            false,
            [
                new(
                    "OR",
                    false,
                    [
                        new(
                            "OR",
                            false,
                            [
                                new(
                                    true,
                                    cpe,
                                    "00000000-0000-0000-0000-000000000001",
                                    null,
                                    null,
                                    null,
                                    null,
                                    RemoteAdvisoryCpeAlignment.Proven,
                                    true,
                                    false),
                            ]),
                    ]),
            ],
            ["Candidate association only."]);
        var match = new RemoteAdvisoryMatch(
            "CVE-2026-42424",
            "candidate",
            "remote_banner_match",
            "OpenSSH",
            "9.6p1",
            cpe,
            "SSH-2.0-OpenSSH_9.6p1",
            RemoteAdvisoryConfidence.Strong,
            "Analyzed",
            DateTimeOffset.UnixEpoch,
            applicability,
            RemoteAdvisorySeverity.High,
            "nvd@nist.gov/CVSS:3.1",
            "Fixture candidate.",
            ["https://example.invalid/reference"],
            false,
            "not_assessed");
        return new(
            RemoteAdvisoryStatus.Complete,
            RemoteAdvisoryResult.ProviderName,
            RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
            DateTimeOffset.UnixEpoch,
            [match],
            []);
    }

    private static int CountOccurrences(string value, string needle)
    {
        var count = 0;
        var startIndex = 0;
        while ((startIndex = value.IndexOf(needle, startIndex, StringComparison.Ordinal)) >= 0)
        {
            count++;
            startIndex += needle.Length;
        }

        return count;
    }

    private static RemoteAuditOptions Options(IReadOnlyList<string> targets, bool online) =>
        new(
            "test",
            new(string.Join(',', targets), targets, targets.Count > 1),
            [22],
            ProbeDepth.Passive,
            true,
            online,
            8,
            100,
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromMilliseconds(100),
            null);

    private sealed class FixedHostScanner(RemoteProductConfidence confidence) : IRemoteHostScanner
    {
        public Task<RemoteHostReport> ScanAsync(
            RemoteScanOptions options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = new RemoteProductCandidate(
                "OpenSSH",
                "9.6p1",
                confidence,
                confidence == RemoteProductConfidence.BannerPattern
                    ? "passive-greeting"
                    : "passive-http-head:server",
                "SSH-2.0-OpenSSH_9.6p1");
            return Task.FromResult(new RemoteHostReport(
                options.Target,
                ["192.0.2.99"],
                [
                    new(
                        "192.0.2.99",
                        "ipv4",
                        22,
                        RemotePortState.Open,
                        1,
                        [
                            new(
                                RemoteFingerprintKind.Ssh,
                                "ssh",
                                RemoteFingerprintConfidence.ProtocolConfirmed,
                                "passive-greeting",
                                "SSH-2.0-OpenSSH_9.6p1",
                                RemoteFingerprint.ReadOnlyAttributes()),
                        ],
                        [candidate],
                        []),
                ],
                []));
        }
    }

    private sealed class DistinctIdentityHostScanner : IRemoteHostScanner
    {
        public Task<RemoteHostReport> ScanAsync(
            RemoteScanOptions options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var separator = options.Target.IndexOf('-', StringComparison.Ordinal);
            var suffixEnd = options.Target.IndexOf('.', separator);
            var suffix = options.Target[(separator + 1)..suffixEnd];
            var version = $"9.{int.Parse(suffix, System.Globalization.CultureInfo.InvariantCulture)}p1";
            var evidence = $"SSH-2.0-OpenSSH_{version}";
            return Task.FromResult(new RemoteHostReport(
                options.Target,
                ["192.0.2.99"],
                [
                    new(
                        "192.0.2.99",
                        "ipv4",
                        22,
                        RemotePortState.Open,
                        1,
                        [],
                        [new("OpenSSH", version, RemoteProductConfidence.BannerPattern, "passive-greeting", evidence)],
                        []),
                ],
                []));
        }
    }

    private sealed class FixedPortStateHostScanner(RemotePortState state) : IRemoteHostScanner
    {
        public Task<RemoteHostReport> ScanAsync(
            RemoteScanOptions options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new RemoteHostReport(
                options.Target,
                ["192.0.2.99"],
                [new("192.0.2.99", "ipv4", 22, state, 100, [], [], [])],
                []));
        }
    }

    private sealed class LeakyDiagnosticHostScanner : IRemoteHostScanner
    {
        public Task<RemoteHostReport> ScanAsync(
            RemoteScanOptions options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            const string address = "203.0.113.77";
            const string evidence = "SSH-2.0-OpenSSH_9.6p1";
            return Task.FromResult(new RemoteHostReport(
                options.Target,
                [address],
                [
                    new(
                        address,
                        "ipv4",
                        22,
                        RemotePortState.Open,
                        1,
                        [
                            new(
                                RemoteFingerprintKind.Ssh,
                                "ssh",
                                RemoteFingerprintConfidence.ProtocolConfirmed,
                                "passive-greeting",
                                evidence,
                                RemoteFingerprint.ReadOnlyAttributes(new Dictionary<string, string>
                                {
                                    ["allow"] = "GET, secret-allow-detail",
                                    ["protocolVersion"] = "2.0",
                                })),
                        ],
                        [new(
                            "OpenSSH",
                            "9.6p1",
                            RemoteProductConfidence.BannerPattern,
                            "passive-greeting",
                            evidence)],
                        [new(
                            "port_fixture_error",
                            "Socket failure at 203.0.113.77:22 secret-port-detail.")]),
                ],
                [new(
                    "host_fixture_error",
                    "Target private.example failed with secret-host-detail.")]));
        }
    }

    private sealed class FixedAdvisoryClient(RemoteAdvisoryResult result) : IRemoteAdvisoryClient
    {
        private int callCount;

        internal int CallCount => Volatile.Read(ref callCount);

        public Task<RemoteAdvisoryResult> EnrichAsync(
            RemoteAdvisoryRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref callCount);
            return Task.FromResult(result);
        }
    }
}
