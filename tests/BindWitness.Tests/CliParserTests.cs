using BindWitness.Cli;
using BindWitness.Domain;

namespace BindWitness.Tests;

public sealed class CliParserTests
{
    [Fact]
    public void Parse_NoArguments_ListsWithoutSlowFirewallCollection()
    {
        var result = CliParser.Parse([]);

        Assert.Equal(CommandKind.List, result.Command);
        Assert.False(result.IncludeFirewall);
    }

    [Theory]
    [InlineData("8080", null, 8080)]
    [InlineData("tcp:443", TransportProtocol.Tcp, 443)]
    [InlineData("udp:53", TransportProtocol.Udp, 53)]
    public void Parse_DirectQuery_EnablesFirewallByDefault(
        string query,
        TransportProtocol? protocol,
        int port)
    {
        var result = CliParser.Parse([query]);

        Assert.Equal(CommandKind.Inspect, result.Command);
        Assert.Equal(protocol, result.Protocol);
        Assert.Equal(port, result.Port);
        Assert.True(result.IncludeFirewall);
    }

    [Fact]
    public void Parse_DirectQuery_CanSkipFirewall()
    {
        var result = CliParser.Parse(["tcp:8080", "--no-firewall"]);

        Assert.False(result.IncludeFirewall);
    }

    [Fact]
    public void Parse_Check_RequiresLockfile()
    {
        var error = Assert.Throws<CliUsageException>(() => CliParser.Parse(["check"]));

        Assert.Contains("lockfile", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("tcp:nope")]
    public void Parse_InvalidQuery_Throws(string query)
    {
        Assert.Throws<CliUsageException>(() => CliParser.Parse([query]));
    }

    [Fact]
    public void Parse_WatchOptions_UsesBoundedInterval()
    {
        var result = CliParser.Parse(["watch", "--interval", "500ms", "--iterations", "2", "--json"]);

        Assert.Equal(TimeSpan.FromMilliseconds(500), result.Interval);
        Assert.Equal(2, result.Iterations);
        Assert.True(result.Json);
    }

    [Theory]
    [InlineData("--process", "server.exe")]
    [InlineData("--scope", "wildcard")]
    public void Parse_LockRejectsMetadataSelectorsThatCouldFailOpen(string option, string value)
    {
        var error = Assert.Throws<CliUsageException>(() => CliParser.Parse(["lock", option, value]));

        Assert.Contains("fail open", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_PrivacyAndBaselineFlags_AreWired()
    {
        var result = CliParser.Parse(
            ["lock", "--include-private", "--resolve-accounts", "--include-udp", "--allow-incomplete"]);

        Assert.True(result.IncludePrivate);
        Assert.True(result.ResolveAccounts);
        Assert.True(result.IncludeUdp);
        Assert.True(result.AllowIncomplete);
    }
}
