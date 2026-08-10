using PortCVE.Cli;
using PortCVE.Collection;
using PortCVE.Domain;
using PortCVE.Remote;
using PortCVE.Remote.Advisories;
using PortCVE.Snapshots;
using PortCVE.Vulnerabilities;

namespace PortCVE.Tests;

public sealed class RemoteCliTests
{
    [Fact]
    public async Task ScanHost_DefaultJsonRedactsNetworkIdentityAndReturnsSuccess()
    {
        var application = Application(
            new FixedHostScanner(includeStrongIdentity: false),
            new NeverAdvisoryClient());
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(
                CommandKind.ScanHost,
                Json: true,
                RemoteTarget: "private.internal",
                RemotePorts: "22",
                Authorized: true),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Contains("\"schema_version\": 1", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("target-001", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("private.internal", output.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(error.ToString());
    }

    [Fact]
    public async Task ScanHost_RuntimeRejectsFailOnWithoutOnlineAdvisories()
    {
        var scanner = new FixedHostScanner(includeStrongIdentity: true);
        var application = Application(scanner, new NeverAdvisoryClient());
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(
                CommandKind.ScanHost,
                RemoteTarget: "192.0.2.10",
                RemotePorts: "22",
                Authorized: true,
                FailOn: VulnerabilitySeverity.High),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.UsageOrSchema, exitCode);
        Assert.Contains("requires --online-advisories", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScanHost_OnlineProviderFailureReturnsIncompleteEvidence()
    {
        var advisory = new FixedAdvisoryClient(new(
            RemoteAdvisoryStatus.Unavailable,
            RemoteAdvisoryResult.ProviderName,
            RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
            null,
            [],
            [new("nvd_timeout", "Fixture timeout.")]));
        var application = Application(new FixedHostScanner(includeStrongIdentity: true), advisory);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(
                CommandKind.ScanHost,
                RemoteTarget: "192.0.2.10",
                RemotePorts: "22",
                Authorized: true,
                OnlineAdvisories: true),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.IncompleteEvidence, exitCode);
        Assert.Equal(1, advisory.CallCount);
        Assert.Contains("nvd_timeout", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScanHost_FailOnCannotPassWithPartialAdvisoryEvidence()
    {
        var advisory = new FixedAdvisoryClient(new(
            RemoteAdvisoryStatus.Partial,
            RemoteAdvisoryResult.ProviderName,
            RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
            DateTimeOffset.UtcNow,
            [],
            [new("nvd_status_partial", "Fixture evidence is partial.")]));
        var application = Application(new FixedHostScanner(includeStrongIdentity: true), advisory);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(
                CommandKind.ScanHost,
                RemoteTarget: "192.0.2.10",
                RemotePorts: "22",
                Authorized: true,
                OnlineAdvisories: true,
                FailOn: VulnerabilitySeverity.High),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.IncompleteEvidence, exitCode);
        Assert.Equal(1, advisory.CallCount);
    }

    [Theory]
    [InlineData("timed_out", true)]
    [InlineData("unreachable", false)]
    public async Task ScanHost_InconclusiveEndpointCannotPassStrictOrFailOn(
        string stateName,
        bool strict)
    {
        var state = stateName switch
        {
            "timed_out" => RemotePortState.TimedOut,
            "unreachable" => RemotePortState.Unreachable,
            _ => throw new ArgumentOutOfRangeException(nameof(stateName)),
        };
        var application = Application(
            new FixedPortStateHostScanner(state),
            new NeverAdvisoryClient());
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(
                CommandKind.ScanHost,
                Json: true,
                Strict: strict,
                RemoteTarget: "192.0.2.10",
                RemotePorts: "22",
                Authorized: true,
                OnlineAdvisories: true,
                FailOn: strict ? null : VulnerabilitySeverity.High),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.IncompleteEvidence, exitCode);
        Assert.Contains("remote_endpoints_incomplete", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScanHost_RuntimeGuardRejectsMissingAuthorization()
    {
        var application = Application(
            new FixedHostScanner(includeStrongIdentity: false),
            new NeverAdvisoryClient());
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(CommandKind.ScanHost, RemoteTarget: "192.0.2.10", RemotePorts: "22"),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.UsageOrSchema, exitCode);
        Assert.Contains("--authorized", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScanHost_RejectsNetworkOutputBeforeAnyTargetConnection()
    {
        var application = Application(new NeverHostScanner(), new NeverAdvisoryClient());
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(
                CommandKind.ScanHost,
                OutputPath: "\\\\fixture.invalid\\share\\remote.json",
                RemoteTarget: "192.0.2.10",
                RemotePorts: "22",
                Authorized: true),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.UsageOrSchema, exitCode);
        Assert.Contains("remote_output_path_network", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScanHost_ResolvedTargetWithNoProbedEndpointsReturnsIncompleteEvidence()
    {
        var application = Application(new EndpointLimitHostScanner(), new NeverAdvisoryClient());
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(
                CommandKind.ScanHost,
                Json: true,
                RemoteTarget: "many-addresses.internal",
                RemotePorts: "all",
                Authorized: true),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.IncompleteEvidence, exitCode);
        Assert.Contains("scan_endpoint_limit_exceeded", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScanHost_StrictDistinctIdentityCapReturnsIncompleteEvidence()
    {
        var advisory = new FixedAdvisoryClient(new(
            RemoteAdvisoryStatus.Complete,
            RemoteAdvisoryResult.ProviderName,
            RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
            DateTimeOffset.UnixEpoch,
            [],
            []));
        var application = Application(
            new ManyIdentityHostScanner(RemoteAuditService.MaximumUniqueAdvisoryIdentities + 1),
            advisory);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(
                CommandKind.ScanHost,
                Json: true,
                Strict: true,
                RemoteTarget: "192.0.2.10",
                RemotePorts: "22",
                Authorized: true,
                OnlineAdvisories: true),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.IncompleteEvidence, exitCode);
        Assert.Equal(RemoteAuditService.MaximumUniqueAdvisoryIdentities, advisory.CallCount);
        Assert.Contains("\"advisory_status\": \"partial\"", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("remote_advisory_identity_limit_exceeded", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScanHost_FailOnUsesNormalizedDirectMatches()
    {
        var advisory = new FixedAdvisoryClient(CompleteHighAdvisoryResult());
        var application = Application(
            new FixedHostScanner(includeStrongIdentity: true),
            advisory);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await application.RunAsync(
            new(
                CommandKind.ScanHost,
                Json: true,
                FailOn: VulnerabilitySeverity.High,
                RemoteTarget: "192.0.2.10",
                RemotePorts: "22",
                Authorized: true,
                OnlineAdvisories: true),
            output,
            error,
            CancellationToken.None);

        Assert.Equal(ExitCodes.NegativeResult, exitCode);
        Assert.Equal(1, advisory.CallCount);
        Assert.Contains("CVE-2026-51515", output.ToString(), StringComparison.Ordinal);
    }

    private static RemoteAdvisoryResult CompleteHighAdvisoryResult()
    {
        const string cpe = "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*";
        var applicability = new RemoteAdvisoryApplicability(
            RemoteAdvisoryApplicabilityDisposition.DirectCandidate,
            true,
            false,
            [],
            ["Candidate association only."]);
        var match = new RemoteAdvisoryMatch(
            "CVE-2026-51515",
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
            [],
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

    private static CliApplication Application(
        IRemoteHostScanner hostScanner,
        IRemoteAdvisoryClient advisoryClient) =>
        new(
            new UnusedSnapshotBuilder(),
            new LockfileService(),
            new VulnerabilityAssessmentTests.FixedScanner(VulnerabilityAssessmentTests.CompleteResult()),
            static path => new(true, Path.GetFullPath(path), "ok", "fixture"),
            hostScanner,
            advisoryClient,
            static () => null);

    private sealed class FixedHostScanner(bool includeStrongIdentity) : IRemoteHostScanner
    {
        public Task<RemoteHostReport> ScanAsync(
            RemoteScanOptions options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyList<RemoteProductCandidate> candidates = includeStrongIdentity
                ? [new("OpenSSH", "9.6p1", RemoteProductConfidence.BannerPattern, "passive-greeting", "SSH-2.0-OpenSSH_9.6p1")]
                : [];
            return Task.FromResult(new RemoteHostReport(
                options.Target,
                ["192.0.2.10"],
                [new("192.0.2.10", "ipv4", 22, RemotePortState.Open, 1, [], candidates, [])],
                []));
        }
    }

    private sealed class NeverAdvisoryClient : IRemoteAdvisoryClient
    {
        public Task<RemoteAdvisoryResult> EnrichAsync(
            RemoteAdvisoryRequest request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("NVD must not be called in this fixture.");
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
                ["192.0.2.10"],
                [new("192.0.2.10", "ipv4", 22, state, 100, [], [], [])],
                []));
        }
    }

    private sealed class NeverHostScanner : IRemoteHostScanner
    {
        public Task<RemoteHostReport> ScanAsync(
            RemoteScanOptions options,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The target scanner must not run in this fixture.");
    }

    private sealed class EndpointLimitHostScanner : IRemoteHostScanner
    {
        public Task<RemoteHostReport> ScanAsync(
            RemoteScanOptions options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new RemoteHostReport(
                options.Target,
                ["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14"],
                [],
                [new(
                    "scan_endpoint_limit_exceeded",
                    "The frozen address and port set exceeded the endpoint limit.")]));
        }
    }

    private sealed class ManyIdentityHostScanner(int identityCount) : IRemoteHostScanner
    {
        public Task<RemoteHostReport> ScanAsync(
            RemoteScanOptions options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidates = Enumerable.Range(0, identityCount)
                .Select(index =>
                {
                    var version = $"9.{index}p1";
                    return new RemoteProductCandidate(
                        "OpenSSH",
                        version,
                        RemoteProductConfidence.BannerPattern,
                        "passive-greeting",
                        $"SSH-2.0-OpenSSH_{version}");
                })
                .ToArray();
            return Task.FromResult(new RemoteHostReport(
                options.Target,
                ["192.0.2.10"],
                [new("192.0.2.10", "ipv4", 22, RemotePortState.Open, 1, [], candidates, [])],
                []));
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

    private sealed class UnusedSnapshotBuilder : ISnapshotBuilder
    {
        public Task<SystemSnapshot> CollectAsync(
            SnapshotOptions options,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Local snapshot collection is not part of remote scans.");
    }
}
