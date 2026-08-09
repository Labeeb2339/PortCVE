using PortCVE.Cli;
using PortCVE.Domain;
using PortCVE.Remote.Imports;
using PortCVE.Vulnerabilities;

namespace PortCVE.Tests;

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

    [Fact]
    public void Parse_ScanExactTcpSubjectAndPolicyFlags_AreWired()
    {
        var result = CliParser.Parse(
            ["scan", "tcp:8080", "--sbom", "fixture.cdx.json", "--fail-on", "high", "--strict", "--json"]);

        Assert.Equal(CommandKind.Scan, result.Command);
        Assert.Equal(8080, result.Port);
        Assert.Equal(TransportProtocol.Tcp, result.Protocol);
        Assert.Equal("fixture.cdx.json", result.SbomPath);
        Assert.Equal(VulnerabilitySeverity.High, result.FailOn);
        Assert.True(result.Strict);
        Assert.True(result.Json);
        Assert.False(result.IncludeFirewall);
    }

    [Fact]
    public void Parse_ScanAll_IsTcpOnly()
    {
        var result = CliParser.Parse(["scan", "--all"]);

        Assert.True(result.All);
        Assert.Equal(TransportProtocol.Tcp, result.Protocol);
    }

    [Fact]
    public void Parse_ScanHost_PentestOptionsAreWired()
    {
        var result = CliParser.Parse(
        [
            "scan-host", "192.0.2.0/30", "--ports", "22,80,443,8000-8002", "--active",
            "--authorized", "--online-advisories", "--concurrency", "64", "--rate", "250", "--connect-timeout", "750ms",
            "--read-timeout", "2s", "--max-hosts", "16", "--fail-on", "high", "--json",
        ]);

        Assert.Equal(CommandKind.ScanHost, result.Command);
        Assert.Equal("192.0.2.0/30", result.RemoteTarget);
        Assert.Equal("22,80,443,8000-8002", result.RemotePorts);
        Assert.True(result.Active);
        Assert.True(result.Authorized);
        Assert.True(result.OnlineAdvisories);
        Assert.Equal(64, result.Concurrency);
        Assert.Equal(250, result.Rate);
        Assert.Equal(TimeSpan.FromMilliseconds(750), result.ConnectTimeout);
        Assert.Equal(TimeSpan.FromSeconds(2), result.ReadTimeout);
        Assert.Equal(16, result.MaximumHosts);
        Assert.Equal(VulnerabilitySeverity.High, result.FailOn);
        Assert.True(result.Json);
    }

    [Fact]
    public void Parse_ScanHost_AllowsExplicitMaximumEngagementSize()
    {
        var result = CliParser.Parse(
            ["scan-host", "10.20.0.0/16", "--authorized", "--max-hosts", "65536", "--ports", "443"]);

        Assert.Equal(65536, result.MaximumHosts);
        Assert.Equal("443", result.RemotePorts);
    }

    [Theory]
    [InlineData("nmap", RemoteImportFormat.NmapXml)]
    [InlineData("nmap-xml", RemoteImportFormat.NmapXml)]
    [InlineData("nuclei", RemoteImportFormat.NucleiJsonl)]
    [InlineData("nuclei-jsonl", RemoteImportFormat.NucleiJsonl)]
    public void Parse_ImportFormatPathAndOutputFlags_AreWired(
        string format,
        RemoteImportFormat expectedFormat)
    {
        var result = CliParser.Parse(
            ["import", format, "results.fixture", "--output", "normalized.json", "--force", "--strict", "--json"]);

        Assert.Equal(CommandKind.Import, result.Command);
        Assert.Equal(expectedFormat, result.ImportFormat);
        Assert.Equal("results.fixture", result.InputPath);
        Assert.Equal("normalized.json", result.OutputPath);
        Assert.True(result.Force);
        Assert.True(result.Strict);
        Assert.True(result.Json);
    }

    [Theory]
    [InlineData("import")]
    [InlineData("import", "nmap")]
    [InlineData("import", "unknown", "results.txt")]
    [InlineData("import", "nmap", "results.xml", "extra")]
    [InlineData("import", "nmap", "results.xml", "--include-private")]
    [InlineData("import", "nuclei", "results.jsonl", "--active")]
    [InlineData("import", "nuclei", "results.jsonl", "--fail-on", "high")]
    public void Parse_InvalidImportCombinations_AreRejected(params string[] arguments)
    {
        Assert.Throws<CliUsageException>(() => CliParser.Parse(arguments));
    }

    [Theory]
    [InlineData("scan-host")]
    [InlineData("scan-host", "example.com", "extra")]
    [InlineData("scan-host", "example.com")]
    [InlineData("scan-host", "example.com", "--all")]
    [InlineData("scan-host", "example.com", "--active")]
    [InlineData("scan-host", "example.com", "--firewall")]
    [InlineData("scan-host", "example.com", "--concurrency", "0")]
    [InlineData("scan-host", "example.com", "--rate", "10001")]
    [InlineData("scan-host", "example.com", "--authorized", "--max-hosts", "65537")]
    [InlineData("scan-host", "example.com", "--authorized", "--fail-on", "high")]
    [InlineData("scan-host", "example.com", "--connect-timeout", "31s")]
    [InlineData("list", "--ports", "80")]
    [InlineData("scan", "tcp:443", "--active")]
    public void Parse_InvalidScanHostCombinations_AreRejected(params string[] arguments)
    {
        Assert.Throws<CliUsageException>(() => CliParser.Parse(arguments));
    }

    [Theory]
    [InlineData("scan")]
    [InlineData("scan", "udp:53")]
    [InlineData("scan", "tcp:443", "--all")]
    [InlineData("scan", "--all", "--sbom", "fixture.json")]
    [InlineData("scan", "tcp:443", "--firewall")]
    [InlineData("scan", "tcp:443", "--force")]
    [InlineData("scan", "tcp:443", "--allow-incomplete")]
    [InlineData("list", "--fail-on", "high")]
    public void Parse_InvalidScanCombinations_AreRejected(params string[] arguments)
    {
        Assert.Throws<CliUsageException>(() => CliParser.Parse(arguments));
    }

    [Theory]
    [InlineData("low")]
    [InlineData("medium")]
    [InlineData("unknown")]
    public void Parse_FailOnAcceptsOnlyHighOrCritical(string severity)
    {
        var error = Assert.Throws<CliUsageException>(() =>
            CliParser.Parse(["scan", "tcp:443", "--fail-on", severity]));

        Assert.Contains("high or critical", error.Message, StringComparison.OrdinalIgnoreCase);
    }
}
