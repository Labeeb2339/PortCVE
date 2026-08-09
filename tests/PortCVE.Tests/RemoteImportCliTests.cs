using System.Text;
using System.Text.Json;
using PortCVE.Cli;

namespace PortCVE.Tests;

public sealed class RemoteImportCliTests
{
    [Fact]
    public async Task ImportNmap_EmitsSchemaV1ThroughRealCliDispatch()
    {
        const string xml = """
            <?xml version="1.0"?>
            <nmaprun scanner="nmap" version="7.98" xmloutputversion="1.05">
              <host>
                <address addr="192.0.2.10" addrtype="ipv4" />
                <ports>
                  <port protocol="tcp" portid="443">
                    <state state="open" reason="syn-ack" />
                  </port>
                </ports>
              </host>
              <runstats><finished exit="success" /></runstats>
            </nmaprun>
            """;
        var inputPath = TemporaryFile("scan.xml", xml);
        try
        {
            using var output = new StringWriter();
            using var error = new StringWriter();
            var exitCode = await new CliApplication().RunAsync(
                CliParser.Parse(["import", "nmap", inputPath]),
                output,
                error,
                CancellationToken.None);

            Assert.Equal(ExitCodes.Success, exitCode);
            Assert.Equal(string.Empty, error.ToString());
            using var document = JsonDocument.Parse(output.ToString());
            Assert.Equal(1, document.RootElement.GetProperty("schema_version").GetInt32());
            Assert.Equal("nmap_xml", document.RootElement.GetProperty("source").GetString());
            Assert.True(document.RootElement.GetProperty("is_complete").GetBoolean());
            Assert.Single(document.RootElement.GetProperty("endpoints").EnumerateArray());
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(inputPath)!, recursive: true);
        }
    }

    [Fact]
    public async Task ImportNuclei_OutputFileIsLocalVersionedJsonAndDoesNotReplaceInput()
    {
        const string jsonl = """
            {"template-id":"tls-version","info":{"name":"TLS observation","severity":"medium"},"host":"https://192.0.2.10","port":"443"}
            """;
        var inputPath = TemporaryFile("findings.jsonl", jsonl);
        var directory = Path.GetDirectoryName(inputPath)!;
        var outputPath = Path.Combine(directory, "normalized.json");
        try
        {
            using var output = new StringWriter();
            using var error = new StringWriter();
            var exitCode = await new CliApplication().RunAsync(
                CliParser.Parse(["import", "nuclei", inputPath, "--output", outputPath]),
                output,
                error,
                CancellationToken.None);

            Assert.Equal(ExitCodes.Success, exitCode);
            Assert.Equal(string.Empty, error.ToString());
            Assert.True(File.Exists(outputPath));
            Assert.Equal(
                JsonDocument.Parse(output.ToString()).RootElement.GetRawText(),
                JsonDocument.Parse(File.ReadAllText(outputPath)).RootElement.GetRawText());

            using var sameFileError = new StringWriter();
            var sameFileExitCode = await new CliApplication().RunAsync(
                CliParser.Parse(["import", "nuclei", inputPath, "--output", inputPath, "--force"]),
                TextWriter.Null,
                sameFileError,
                CancellationToken.None);
            Assert.Equal(ExitCodes.UsageOrSchema, sameFileExitCode);
            Assert.Contains("must not replace", sameFileError.ToString(), StringComparison.Ordinal);
            Assert.Equal(jsonl, File.ReadAllText(inputPath));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task ImportNmap_StrictReturnsIncompleteWithoutDiscardingValidEvidence()
    {
        const string xml = """
            <nmaprun scanner="nmap" version="7.98">
              <host>
                <address addr="192.0.2.10" addrtype="ipv4" />
                <ports><port protocol="tcp" portid="443"><state state="open" /></port></ports>
              </host>
              <host><ports><port protocol="tcp" portid="80" /></ports></host>
              <host>
                <address addr="192.0.2.11" addrtype="ipv4" />
                <ports><port protocol="sctp" portid="3868" /></ports>
              </host>
              <runstats><finished exit="success" /></runstats>
            </nmaprun>
            """;
        var inputPath = TemporaryFile("incomplete.xml", xml);
        try
        {
            using var output = new StringWriter();
            using var error = new StringWriter();
            var exitCode = await new CliApplication().RunAsync(
                CliParser.Parse(["import", "nmap", inputPath, "--strict"]),
                output,
                error,
                CancellationToken.None);

            Assert.Equal(ExitCodes.IncompleteEvidence, exitCode);
            using var document = JsonDocument.Parse(output.ToString());
            Assert.False(document.RootElement.GetProperty("is_complete").GetBoolean());
            Assert.Contains(
                document.RootElement.GetProperty("diagnostics").EnumerateArray(),
                static item => item.GetProperty("code").GetString() == "nmap_host_without_address");
            Assert.Contains(
                document.RootElement.GetProperty("diagnostics").EnumerateArray(),
                static item => item.GetProperty("code").GetString() == "nmap_protocol_ignored");
            Assert.DoesNotContain(
                document.RootElement.GetProperty("diagnostics").EnumerateArray(),
                static item => item.GetProperty("code").GetString() == "nmap_scan_incomplete");
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(inputPath)!, recursive: true);
        }
    }

    private static string TemporaryFile(string fileName, string contents)
    {
        var directory = Path.Combine(Path.GetTempPath(), $"portcve-import-cli-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, fileName);
        File.WriteAllText(path, contents, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return path;
    }
}
