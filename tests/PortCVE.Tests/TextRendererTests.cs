using PortCVE.Domain;
using PortCVE.Output;

namespace PortCVE.Tests;

public sealed class TextRendererTests
{
    [Fact]
    public void RenderDetails_HostAllowNeverClaimsInternetReachability()
    {
        var listener = new ListenerEvidence(
            "tcp/ipv4/0.0.0.0/8080",
            TransportProtocol.Tcp,
            IpFamily.Ipv4,
            "0.0.0.0",
            8080,
            "LISTEN",
            BindScope.Wildcard,
            "all IPv4 interfaces",
            new(10, null, "web.exe", "C:\\web.exe", null, null, null, null, null, [], false, true, []),
            [new("wifi", "Wi-Fi", 7, "192.168.1.10", 24, "Private", true)],
            new(FirewallVerdict.Allow, Confidence.Medium, "Host permits.", [], []),
            [],
            []);
        using var writer = new StringWriter();

        TextRenderer.RenderDetails([listener], false, writer);
        var text = writer.ToString();

        Assert.Contains("STATIC HOST POLICY INDICATES ALLOW - packet path not tested", text, StringComparison.Ordinal);
        Assert.Contains("LISTENING - application acceptance was not tested", text, StringComparison.Ordinal);
        Assert.Contains("Internet", text, StringComparison.Ordinal);
        Assert.Contains("UNKNOWN", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Internet     YES", text, StringComparison.Ordinal);
        Assert.DoesNotContain("This machine YES", text, StringComparison.Ordinal);
    }

    [Fact]
    public void RenderDetails_UdpBindDoesNotClaimReceiveBehavior()
    {
        var listener = new ListenerEvidence(
            "udp/ipv4/0.0.0.0/5353",
            TransportProtocol.Udp,
            IpFamily.Ipv4,
            "0.0.0.0",
            5353,
            "BOUND",
            BindScope.Wildcard,
            "all IPv4 interfaces",
            new(10, null, "mdns.exe", null, null, null, null, null, null, [], false, false, []),
            [],
            HostPolicyEvidence.NotEvaluated,
            [],
            []);
        using var writer = new StringWriter();

        TextRenderer.RenderDetails([listener], false, writer);

        Assert.Contains("BOUND - receive behavior was not proven", writer.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void RenderDetails_CorrelatedContainerShowsPublishedMapping()
    {
        var listener = new ListenerEvidence(
            "tcp/ipv4/0.0.0.0/8080",
            TransportProtocol.Tcp,
            IpFamily.Ipv4,
            "0.0.0.0",
            8080,
            "LISTEN",
            BindScope.Wildcard,
            "all IPv4 interfaces",
            new(10, null, "docker-backend.exe", null, null, null, null, null, null, [], false, false, []),
            [],
            HostPolicyEvidence.NotEvaluated,
            [],
            [],
            [
                new(
                    "docker",
                    "container-id",
                    "web",
                    "example/web:1.0",
                    "sha256:image-id",
                    "0.0.0.0",
                    8080,
                    80,
                    TransportProtocol.Tcp,
                    Confidence.Medium,
                    ["tuple correlation"]),
            ]);
        using var writer = new StringWriter();

        TextRenderer.RenderDetails([listener], false, writer);
        var text = writer.ToString();

        Assert.Contains("CONTAINER PUBLICATION", text, StringComparison.Ordinal);
        Assert.Contains("web  (docker)", text, StringComparison.Ordinal);
        Assert.Contains("0.0.0.0:8080 -> 80/tcp", text, StringComparison.Ordinal);
        Assert.Contains("tuple correlation", text, StringComparison.Ordinal);
    }
}
