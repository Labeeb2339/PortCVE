using PortCVE.Collection;
using PortCVE.Domain;

namespace PortCVE.Tests;

public sealed class WindowsFirewallPolicyTests
{
    [Fact]
    public void Assess_ExactPortAllow_ReturnsHostPermit()
    {
        var policy = Policy(
            Rule("allow-web", "Allow Web", "Allow"),
            Port("allow-web", "TCP", "8080"));

        var result = policy.Assess(Listener());

        Assert.Equal(FirewallVerdict.Allow, result.Verdict);
        Assert.Single(result.MatchingRules);
        Assert.Contains("static host policy indicates allow", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Assess_ExactBlockAndAllow_BlockTakesPrecedence()
    {
        var policy = Policy(
            [Rule("allow", "Allow", "Allow"), Rule("block", "Block", "Block")],
            [Port("allow", "TCP", "8080"), Port("block", "TCP", "8080")]);

        var result = policy.Assess(Listener());

        Assert.Equal(FirewallVerdict.Block, result.Verdict);
        Assert.Equal(2, result.MatchingRules.Count);
    }

    [Fact]
    public void Assess_UnrelatedProgramRule_DoesNotMatch()
    {
        var policy = Policy(
            [Rule("other", "Other App", "Allow")],
            [Port("other", "TCP", "8080")],
            [Application("other", "C:\\Apps\\other.exe")]);

        var result = policy.Assess(Listener());

        Assert.Equal(FirewallVerdict.Block, result.Verdict);
        Assert.Empty(result.MatchingRules);
    }

    [Fact]
    public void Assess_RemoteAddressConstrainedAllow_ReturnsMixedNotPermit()
    {
        var policy = Policy(
            [Rule("local-only", "Local subnet", "Allow")],
            [Port("local-only", "TCP", "8080")],
            addresses: [Address("local-only", "Any", "LocalSubnet")]);

        var result = policy.Assess(Listener());

        Assert.Equal(FirewallVerdict.Mixed, result.Verdict);
        Assert.Equal(Confidence.Low, result.Confidence);
        Assert.Empty(result.MatchingRules);
    }

    [Fact]
    public void Assess_UnknownActiveInterface_ForcesIncompleteMixedVerdict()
    {
        var policy = Policy(
            Rule("allow-web", "Allow Web", "Allow"),
            Port("allow-web", "TCP", "8080"));
        var listener = Listener() with
        {
            ActiveOn =
            [
                new("wifi", "Wi-Fi", 7, "192.168.1.10", 24, "Public", true),
                new("vpn", "VPN", 11, "10.10.0.2", 24, "Unknown", true),
            ],
        };

        var result = policy.Assess(listener);

        Assert.Equal(FirewallVerdict.Mixed, result.Verdict);
        Assert.Equal(Confidence.Low, result.Confidence);
        Assert.Contains(result.Limitations, static item => item.Contains("no mapped", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Assess_AuthenticatedBypassAgainstBlock_ReturnsMixed()
    {
        var rules = new[]
        {
            Rule("block", "Block", "Block"),
            Rule("bypass", "Authenticated bypass", "Allow"),
        };
        var policy = Policy(
            rules,
            [Port("block", "TCP", "8080"), Port("bypass", "TCP", "8080")],
            security:
            [
                Security("block"),
                Security("bypass", overrideBlockRules: true),
            ]);

        var result = policy.Assess(Listener());

        Assert.Equal(FirewallVerdict.Mixed, result.Verdict);
        Assert.Equal(Confidence.Low, result.Confidence);
    }

    [Fact]
    public void NetworkProfile_DomainAuthenticated_NormalizesToDomain()
    {
        Assert.Equal("Domain", NetworkInterfaceCollector.NormalizeProfile("DomainAuthenticated"));
        Assert.Equal("Public", NetworkInterfaceCollector.NormalizeProfile("Public"));
    }

    private static WindowsFirewallPolicy Policy(
        WindowsFirewallCollector.FirewallRuleRow rule,
        WindowsFirewallCollector.PortFilterRow port) => Policy([rule], [port]);

    private static WindowsFirewallPolicy Policy(
        WindowsFirewallCollector.FirewallRuleRow[] rules,
        WindowsFirewallCollector.PortFilterRow[] ports,
        WindowsFirewallCollector.ApplicationFilterRow[]? applications = null,
        WindowsFirewallCollector.AddressFilterRow[]? addresses = null,
        WindowsFirewallCollector.SecurityFilterRow[]? security = null)
    {
        var document = new WindowsFirewallCollector.FirewallDocument(
            [new("Public", true, "Block", false)],
            rules,
            ports,
            addresses ?? rules.Select(static item => Address(item.Id, "Any", "Any")).ToArray(),
            applications ?? rules.Select(static item => Application(item.Id, "Any")).ToArray(),
            rules.Select(static item => new WindowsFirewallCollector.ServiceFilterRow(item.Id, "Any")).ToArray(),
            rules.Select(static item => new WindowsFirewallCollector.InterfaceFilterRow(item.Id, "Any")).ToArray(),
            rules.Select(static item => new WindowsFirewallCollector.InterfaceTypeFilterRow(item.Id, "Any")).ToArray(),
            security ?? rules.Select(static item => new WindowsFirewallCollector.SecurityFilterRow(
                item.Id,
                "NotRequired",
                "NotRequired",
                false,
                string.Empty,
                string.Empty,
                string.Empty)).ToArray());
        return WindowsFirewallPolicy.FromDocument(document);
    }

    private static WindowsFirewallCollector.FirewallRuleRow Rule(string id, string name, string action) =>
        new(id, name, action, "Public", "Block", "Full", string.Empty, "False", "False");

    private static WindowsFirewallCollector.PortFilterRow Port(string id, string protocol, string port) =>
        new(id, protocol, port, "Any", string.Empty, string.Empty);

    private static WindowsFirewallCollector.AddressFilterRow Address(string id, string local, string remote) =>
        new(id, local, remote);

    private static WindowsFirewallCollector.ApplicationFilterRow Application(string id, string program) =>
        new(id, program, string.Empty);

    private static WindowsFirewallCollector.SecurityFilterRow Security(string id, bool overrideBlockRules = false) =>
        new(id, "NotRequired", "NotRequired", overrideBlockRules, string.Empty, string.Empty, string.Empty);

    private static ListenerEvidence Listener() => new(
        "tcp/ipv4/0.0.0.0/8080",
        TransportProtocol.Tcp,
        IpFamily.Ipv4,
        "0.0.0.0",
        8080,
        "LISTEN",
        BindScope.Wildcard,
        "all IPv4 interfaces",
        new(100, DateTimeOffset.UnixEpoch, "server.exe", "C:\\Apps\\server.exe", null, null, null, "S-1", "TEST\\user", [], false, true, []),
        [new("wifi", "Wi-Fi", 7, "192.168.1.10", 24, "Public", true)],
        HostPolicyEvidence.NotEvaluated,
        [],
        []);
}
