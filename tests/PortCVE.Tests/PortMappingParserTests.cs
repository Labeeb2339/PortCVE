using PortCVE.Domain;
using PortCVE.Verification;

namespace PortCVE.Tests;

public sealed class PortMappingParserTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_EmptyValueProducesNoOverrides(string? value)
    {
        var mappings = PortMappingParser.Parse(value);

        Assert.Empty(mappings);
    }

    [Fact]
    public void Parse_NormalizesTcpAndUdpMappings()
    {
        var mappings = PortMappingParser.Parse(" TCP/443 = tcp/8443, udp/53=UDP/5353 ");

        Assert.Equal(2, mappings.Count);
        Assert.Equal(
            new VerificationEndpointKey(TransportProtocol.Tcp, 8443),
            mappings[new(TransportProtocol.Tcp, 443)]);
        Assert.Equal(
            new VerificationEndpointKey(TransportProtocol.Udp, 5353),
            mappings[new(TransportProtocol.Udp, 53)]);
    }

    [Fact]
    public void Parse_RejectsDuplicateExternalEndpoint()
    {
        var exception = Assert.Throws<VerificationInputException>(() =>
            PortMappingParser.Parse("tcp/443=tcp/8443,TCP/443=tcp/9443"));

        Assert.Contains("duplicated", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_RejectsTransportChanges()
    {
        var exception = Assert.Throws<VerificationInputException>(() =>
            PortMappingParser.Parse("tcp/53=udp/53"));

        Assert.Contains("transport protocol", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("tcp/443")]
    [InlineData("tcp/443=tcp/8443=extra")]
    [InlineData("sctp/443=tcp/443")]
    [InlineData("tcp/0=tcp/443")]
    [InlineData("tcp/65536=tcp/443")]
    [InlineData("tcp/not-a-port=tcp/443")]
    [InlineData("tcp:443=tcp/8443")]
    [InlineData("0/443=0/8443")]
    [InlineData("tcp/+443=tcp/8443")]
    public void Parse_RejectsMalformedMappings(string value)
    {
        Assert.Throws<VerificationInputException>(() => PortMappingParser.Parse(value));
    }

    [Theory]
    [InlineData(",")]
    [InlineData("tcp/443=tcp/8443,")]
    [InlineData(",tcp/443=tcp/8443")]
    [InlineData("tcp/443=tcp/8443,,udp/53=udp/53")]
    public void Parse_RejectsEmptyMappingItems(string value)
    {
        Assert.Throws<VerificationInputException>(() => PortMappingParser.Parse(value));
    }
}
