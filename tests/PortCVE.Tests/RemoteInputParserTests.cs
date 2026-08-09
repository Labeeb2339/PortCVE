using PortCVE.Remote;

namespace PortCVE.Tests;

public sealed class RemoteInputParserTests
{
    [Fact]
    public void ParsePorts_CommonDefault_IsDeterministicAndUnique()
    {
        var ports = RemoteInputParser.ParsePorts(null);

        Assert.Contains(22, ports);
        Assert.Contains(443, ports);
        Assert.Contains(3389, ports);
        Assert.Equal(ports.Order().Distinct(), ports);
    }

    [Fact]
    public void ParsePorts_ListRangesAndDuplicates_AreNormalized()
    {
        var ports = RemoteInputParser.ParsePorts("443,80,8000-8002,80");

        Assert.Equal([80, 443, 8000, 8001, 8002], ports);
    }

    [Fact]
    public void ParsePorts_All_SelectsEveryTcpPort()
    {
        var ports = RemoteInputParser.ParsePorts("all");

        Assert.Equal(65535, ports.Count);
        Assert.Equal(1, ports[0]);
        Assert.Equal(65535, ports[^1]);
    }

    [Theory]
    [InlineData("")]
    [InlineData(",80")]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("100-99")]
    [InlineData("80-nope")]
    public void ParsePorts_InvalidSpecification_FailsClosed(string specification)
    {
        Assert.Throws<RemoteInputException>(() => RemoteInputParser.ParsePorts(specification));
    }

    [Fact]
    public void ParseTargets_SingleHostname_IsPreservedForSni()
    {
        var plan = RemoteInputParser.ParseTargets("Example.COM");

        Assert.False(plan.IsRange);
        Assert.Equal("Example.COM", Assert.Single(plan.Targets));
    }

    [Fact]
    public void ParseTargets_Ipv4Cidr_IsCanonicalAndBounded()
    {
        var plan = RemoteInputParser.ParseTargets("192.0.2.5/30", maximumHosts: 4);

        Assert.True(plan.IsRange);
        Assert.Equal(["192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"], plan.Targets);
    }

    [Theory]
    [InlineData("https://example.com")]
    [InlineData("example.com/path")]
    [InlineData("2001:db8::/64")]
    [InlineData("192.0.2.0/33")]
    public void ParseTargets_UnsafeOrUnsupportedSelector_IsRejected(string selector)
    {
        Assert.Throws<RemoteInputException>(() => RemoteInputParser.ParseTargets(selector));
    }

    [Fact]
    public void ParseTargets_CidrBeyondLimit_IsRejectedBeforeExpansion()
    {
        var error = Assert.Throws<RemoteInputException>(() =>
            RemoteInputParser.ParseTargets("10.0.0.0/16", maximumHosts: 256));

        Assert.Contains("65536", error.Message, StringComparison.Ordinal);
    }
}
