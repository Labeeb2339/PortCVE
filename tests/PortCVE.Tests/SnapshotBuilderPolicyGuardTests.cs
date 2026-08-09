using PortCVE.Collection;
using PortCVE.Domain;

namespace PortCVE.Tests;

public sealed class SnapshotBuilderPolicyGuardTests
{
    [Theory]
    [InlineData(CollectorStatus.Partial, FirewallVerdict.Allow)]
    [InlineData(CollectorStatus.Partial, FirewallVerdict.Block)]
    [InlineData(CollectorStatus.Unavailable, FirewallVerdict.Allow)]
    [InlineData(CollectorStatus.Failed, FirewallVerdict.Disabled)]
    public void Guard_IncompleteInterfacesDowngradeDefiniteNonLoopbackVerdict(
        CollectorStatus interfaceStatus,
        FirewallVerdict verdict)
    {
        var assessment = Assessment(verdict, Confidence.Medium);

        var result = SnapshotBuilder.GuardHostPolicyForInterfaceCollection(
            BindScope.Wildcard,
            interfaceStatus,
            assessment);

        Assert.Equal(FirewallVerdict.Unknown, result.Verdict);
        Assert.Equal(Confidence.Low, result.Confidence);
        Assert.Equal(assessment.MatchingRules, result.MatchingRules);
        Assert.Contains("existing limitation", result.Limitations);
        Assert.Contains(
            result.Limitations,
            limitation => limitation.Contains(interfaceStatus.ToString(), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Guard_IncompleteInterfacesKeepMixedVerdictAtLowConfidence()
    {
        var assessment = Assessment(FirewallVerdict.Mixed, Confidence.Medium);

        var result = SnapshotBuilder.GuardHostPolicyForInterfaceCollection(
            BindScope.Interface,
            CollectorStatus.Partial,
            assessment);

        Assert.Equal(FirewallVerdict.Mixed, result.Verdict);
        Assert.Equal(Confidence.Low, result.Confidence);
    }

    [Theory]
    [InlineData(BindScope.Wildcard, CollectorStatus.Complete)]
    [InlineData(BindScope.Loopback, CollectorStatus.Partial)]
    public void Guard_CompleteInterfacesOrLoopbackReturnOriginalAssessment(
        BindScope bindScope,
        CollectorStatus interfaceStatus)
    {
        var assessment = Assessment(FirewallVerdict.Allow, Confidence.Medium);

        var result = SnapshotBuilder.GuardHostPolicyForInterfaceCollection(
            bindScope,
            interfaceStatus,
            assessment);

        Assert.Same(assessment, result);
    }

    private static HostPolicyEvidence Assessment(FirewallVerdict verdict, Confidence confidence) => new(
        verdict,
        confidence,
        "Original static assessment.",
        [],
        ["existing limitation"]);
}
