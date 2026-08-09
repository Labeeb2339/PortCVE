using System.Text.Json;
using PortCVE.Collection;

namespace PortCVE.Tests;

public sealed class DockerPublishedPortParserTests
{
    [Fact]
    public void ParseApiVersion_ReturnsValidatedDaemonVersion()
    {
        var result = DockerPublishedPortParser.ParseApiVersion(
            """{"Version":"29.6.1","ApiVersion":"1.55","MinAPIVersion":"1.40"}""");

        Assert.Equal("1.55", result);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("v1.55")]
    [InlineData("1.55/containers")]
    public void ParseApiVersion_RejectsUnsafeVersion(string apiVersion)
    {
        var json = $$"""{"ApiVersion":"{{apiVersion}}"}""";

        Assert.Throws<JsonException>(() => DockerPublishedPortParser.ParseApiVersion(json));
    }

    [Fact]
    public void ParseContainers_ParsesPublishedPortsAndPreservesDuplicateMappings()
    {
        const string json = """
            [
              {
                "Id": "8dfafdbc3a40",
                "Names": ["/web", "/stack-web-1"],
                "Image": "nginx:1.27-alpine",
                "ImageID": "sha256:nginx-image",
                "Command": "nginx -g daemon off;",
                "Ports": [
                  { "IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp" },
                  { "IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp" },
                  { "IP": "::", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp" },
                  { "PrivatePort": 443, "Type": "tcp" }
                ]
              },
              {
                "Id": "dns-container",
                "Names": ["/dns"],
                "Image": "coredns/coredns:latest",
                "ImageID": "sha256:dns-image",
                "Ports": [
                  { "IP": "::1", "PrivatePort": 53, "PublicPort": 5353, "Type": "UDP" },
                  { "PrivatePort": 9000, "PublicPort": 19000, "Type": "tcp" }
                ]
              }
            ]
            """;

        var result = DockerPublishedPortParser.ParseContainers(json);

        Assert.Equal(5, result.Count);
        Assert.Equal(result[0], result[1]);
        Assert.Equal(new DockerPublishedPort(
            "8dfafdbc3a40",
            "web",
            "nginx:1.27-alpine",
            "sha256:nginx-image",
            "0.0.0.0",
            8080,
            80,
            "tcp"), result[0]);
        Assert.Equal("::", result[2].HostAddress);
        Assert.Equal("::1", result[3].HostAddress);
        Assert.Equal("udp", result[3].Protocol);
        Assert.Equal("*", result[4].HostAddress);
        Assert.DoesNotContain(result, static port => port.ContainerPort == 443);
    }

    [Theory]
    [InlineData("0.0.0.0", "192.168.1.20", true)]
    [InlineData("0.0.0.0", "::1", false)]
    [InlineData("::", "fe80::1%2", true)]
    [InlineData("::", "127.0.0.1", false)]
    [InlineData("192.168.1.20", "0.0.0.0", true)]
    [InlineData("192.168.1.20", "192.168.1.20", true)]
    [InlineData("192.168.1.20", "192.168.1.21", false)]
    [InlineData("*", "::1", true)]
    [InlineData("not-an-address", "127.0.0.1", false)]
    [InlineData("127.0.0.1", "not-an-address", false)]
    public void HostAddressMatches_HandlesFamiliesWildcardsAndExactAddresses(
        string publishedAddress,
        string endpointAddress,
        bool expected)
    {
        Assert.Equal(
            expected,
            DockerPublishedPortParser.HostAddressMatches(publishedAddress, endpointAddress));
    }

    [Fact]
    public void ParseContainers_RejectsMalformedJson()
    {
        Assert.ThrowsAny<JsonException>(() => DockerPublishedPortParser.ParseContainers("[{"));
        Assert.Throws<JsonException>(() => DockerPublishedPortParser.ParseContainers("{}"));
    }

    [Fact]
    public void ParseContainers_RejectsInvalidPublishedPort()
    {
        const string json = """
            [{
              "Id": "bad",
              "Names": ["/bad"],
              "Image": "bad:latest",
              "ImageID": "sha256:bad",
              "Ports": [{ "IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 70000, "Type": "tcp" }]
            }]
            """;

        Assert.Throws<JsonException>(() => DockerPublishedPortParser.ParseContainers(json));
    }

    [Fact]
    public void ParseContainers_RejectsUnsupportedPublishedProtocol()
    {
        const string json = """
            [{
              "Id": "bad-protocol",
              "Names": ["/bad-protocol"],
              "Image": "bad:latest",
              "ImageID": "sha256:bad",
              "Ports": [{ "IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "sctp" }]
            }]
            """;

        Assert.Throws<JsonException>(() => DockerPublishedPortParser.ParseContainers(json));
    }
}
