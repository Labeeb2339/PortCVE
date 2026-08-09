using System.Security.Cryptography;
using System.Text;
using PortCVE.Remote.Imports;
using PortCVE.Vulnerabilities;

namespace PortCVE.Tests;

public sealed class RemoteImportServiceTests
{
    [Fact]
    public void ImportNmap_ProducesVersionedDocumentWithStableInputIdentity()
    {
        const string xml = """
            <?xml version="1.0"?>
            <nmaprun scanner="nmap" version="7.98" xmloutputversion="1.05">
              <host>
                <address addr="192.0.2.10" addrtype="ipv4" />
                <ports>
                  <port protocol="tcp" portid="443">
                    <state state="open" reason="syn-ack" />
                    <service name="https" product="fixture" version="1.0" method="probed" conf="10" />
                  </port>
                </ports>
              </host>
              <runstats><finished exit="success" /></runstats>
            </nmaprun>
            """;
        var path = TemporaryFile(".xml", xml);
        try
        {
            var document = new PentestImportService().Import(
                RemoteImportFormat.NmapXml,
                path,
                "test-version",
                strict: true);

            Assert.Equal(PentestImportDocument.CurrentSchemaVersion, document.SchemaVersion);
            Assert.Equal("test-version", document.ToolVersion);
            Assert.Equal("nmap_xml", document.Source);
            Assert.Equal("7.98", document.SourceVersion);
            Assert.True(document.IsComplete);
            Assert.Equal(Path.GetFileName(path), document.Input.FileName);
            Assert.Equal(new FileInfo(path).Length, document.Input.SizeBytes);
            Assert.Equal(
                Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))),
                document.Input.Sha256);
            Assert.Single(document.Endpoints);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ImportNuclei_LenientModePreservesValidRecordsAndMarksDocumentIncomplete()
    {
        const string jsonl = """
            {not-json}
            {"template-id":"not-a-match","info":{"name":"Negative matcher","severity":"info"},"host":"https://192.0.2.10","matcher-status":false}
            {"template-id":"tls-version","info":{"name":"TLS observation","severity":"medium"},"host":"https://192.0.2.10","port":"443"}
            """;
        var path = TemporaryFile(".jsonl", jsonl);
        try
        {
            var document = new PentestImportService().Import(
                RemoteImportFormat.NucleiJsonl,
                path,
                "test-version",
                strict: false);

            Assert.False(document.IsComplete);
            Assert.Single(document.Findings);
            Assert.Contains(document.Diagnostics, static item => item.Code == "nuclei_record_invalid");

            Assert.Throws<InvalidDataException>(() => new PentestImportService().Import(
                RemoteImportFormat.NucleiJsonl,
                path,
                "test-version",
                strict: true));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ImportPathPolicy_RejectsUncAndReparseTraversal()
    {
        var unc = LocalPathPolicy.ValidateExistingImportFile("\\\\server\\share\\results.xml");
        Assert.False(unc.IsValid);
        Assert.Equal("import_path_network", unc.Code);

        var parent = Path.Combine(Path.GetTempPath(), $"portcve-import-link-{Guid.NewGuid():N}");
        var target = Path.Combine(parent, "target");
        var link = Path.Combine(parent, "link");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "results.xml"), "<nmaprun />");
        Directory.CreateSymbolicLink(link, target);
        try
        {
            var validation = LocalPathPolicy.ValidateExistingImportFile(Path.Combine(link, "results.xml"));

            Assert.False(validation.IsValid);
            Assert.Equal("import_path_reparse", validation.Code);
        }
        finally
        {
            Directory.Delete(link);
            Directory.Delete(parent, recursive: true);
        }
    }

    [Fact]
    public void ImportService_StopsBeforeOpeningARejectedPath()
    {
        var service = new PentestImportService(_ =>
            new(false, null, "import_path_network", "The path is not local."));

        var exception = Assert.Throws<ImportPathException>(() => service.Import(
            RemoteImportFormat.NmapXml,
            "ignored.xml",
            "test-version",
            strict: true));

        Assert.Equal("import_path_network", exception.Code);
    }

    [Fact]
    public void ImportService_ObservesCancellationBeforeHashingOrParsingInput()
    {
        var path = TemporaryFile(".jsonl", new string('x', 1024 * 1024));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        try
        {
            Assert.Throws<OperationCanceledException>(() => new PentestImportService().Import(
                RemoteImportFormat.NucleiJsonl,
                path,
                "test-version",
                strict: true,
                cancellation.Token));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string TemporaryFile(string extension, string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"portcve-import-{Guid.NewGuid():N}{extension}");
        File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return path;
    }
}
