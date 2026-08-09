using PortCVE.Collection;
using PortCVE.Domain;

namespace PortCVE.Tests;

public sealed class DockerExposureCorrelatorTests
{
    [Fact]
    public void Correlate_AttachesPublishedContainerByHostTuple()
    {
        var listener = Listener(TransportProtocol.Tcp, IpFamily.Ipv4, "0.0.0.0", 8080);
        var publication = Publication("0.0.0.0", 8080, 80, "tcp");

        var result = DockerExposureCorrelator.Correlate([listener], [publication]);

        var exposure = Assert.Single(Assert.Single(result.Listeners).ContainerExposures!);
        Assert.Equal("web", exposure.ContainerName);
        Assert.Equal("example/web:1.0", exposure.Image);
        Assert.Equal(80, exposure.ContainerPort);
        Assert.Equal(TransportProtocol.Tcp, exposure.Protocol);
        Assert.Equal(Confidence.Medium, exposure.Confidence);
        Assert.Empty(result.UnmatchedPublications);
    }

    [Fact]
    public void Correlate_DoesNotCrossProtocolOrAddressFamily()
    {
        var listener = Listener(TransportProtocol.Tcp, IpFamily.Ipv6, "::", 8080);
        var wrongFamily = Publication("0.0.0.0", 8080, 80, "tcp");
        var wrongProtocol = Publication("::", 8080, 80, "udp");

        var result = DockerExposureCorrelator.Correlate(
            [listener],
            [wrongFamily, wrongProtocol]);

        Assert.Null(Assert.Single(result.Listeners).ContainerExposures);
        Assert.Equal(2, result.UnmatchedPublications.Count);
    }

    [Fact]
    public void Correlate_ConcretePublicationMatchesWildcardHostSocket()
    {
        var listener = Listener(TransportProtocol.Tcp, IpFamily.Ipv4, "0.0.0.0", 8443);
        var publication = Publication("127.0.0.1", 8443, 443, "tcp");

        var result = DockerExposureCorrelator.Correlate([listener], [publication]);

        Assert.Single(Assert.Single(result.Listeners).ContainerExposures!);
        Assert.Empty(result.UnmatchedPublications);
    }

    [Fact]
    public void Correlate_PrefersExactAddressOverWildcardFallback()
    {
        var wildcard = Listener(TransportProtocol.Tcp, IpFamily.Ipv4, "0.0.0.0", 8443);
        var exact = Listener(TransportProtocol.Tcp, IpFamily.Ipv4, "127.0.0.1", 8443);
        var publication = Publication("127.0.0.1", 8443, 443, "tcp");

        var result = DockerExposureCorrelator.Correlate([wildcard, exact], [publication]);

        Assert.Null(result.Listeners[0].ContainerExposures);
        Assert.Single(result.Listeners[1].ContainerExposures!);
        Assert.Empty(result.UnmatchedPublications);
    }

    [Fact]
    public void Correlate_WithholdsAmbiguousPublication()
    {
        var first = Listener(TransportProtocol.Udp, IpFamily.Ipv4, "0.0.0.0", 5353);
        var second = Listener(TransportProtocol.Udp, IpFamily.Ipv4, "0.0.0.0", 5353) with
        {
            Owner = new(200, null, "other.exe", null, null, null, null, null, null, [], false, false, []),
        };
        var publication = Publication("0.0.0.0", 5353, 5353, "udp");

        var result = DockerExposureCorrelator.Correlate([first, second], [publication]);

        Assert.All(result.Listeners, static listener => Assert.Null(listener.ContainerExposures));
        Assert.Single(result.UnmatchedPublications);
    }

    private static DockerPublishedPort Publication(
        string hostAddress,
        int hostPort,
        int containerPort,
        string protocol) => new(
            "container-id",
            "web",
            "example/web:1.0",
            $"sha256:{new string('a', 64)}",
            hostAddress,
            hostPort,
            containerPort,
            protocol);

    private static ListenerEvidence Listener(
        TransportProtocol protocol,
        IpFamily family,
        string address,
        int port) => new(
            $"{protocol.ToString().ToLowerInvariant()}/{family.ToString().ToLowerInvariant()}/{address}/{port}",
            protocol,
            family,
            address,
            port,
            protocol == TransportProtocol.Tcp ? "LISTEN" : "BOUND",
            address is "0.0.0.0" or "::" ? BindScope.Wildcard : BindScope.Interface,
            "test binding",
            new(100, null, "docker-backend.exe", null, null, null, null, null, null, [], false, false, []),
            [],
            HostPolicyEvidence.NotEvaluated,
            [],
            []);
}
