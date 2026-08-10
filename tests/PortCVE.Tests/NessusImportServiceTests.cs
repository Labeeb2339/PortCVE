using System.Security.Cryptography;
using System.Text;
using PortCVE.Remote.Imports;

namespace PortCVE.Tests;

public sealed class NessusImportServiceTests
{
    [Fact]
    public void Import_ProducesVersionedDocumentWithStableInputIdentity()
    {
        const string xml = """
            <NessusClientData_v2 version="10.8">
              <Report name="fixture">
                <ReportHost name="192.0.2.10">
                  <ReportItem port="443" svc_name="https" protocol="tcp" severity="3"
                              pluginID="10001" pluginName="TLS configuration finding">
                    <cve>CVE-2024-12345</cve>
                  </ReportItem>
                </ReportHost>
              </Report>
            </NessusClientData_v2>
            """;
        var path = TemporaryFile(xml);
        try
        {
            var document = new PentestImportService().Import(
                RemoteImportFormat.NessusXml,
                path,
                "test-version",
                strict: true);

            Assert.Equal(PentestImportDocument.CurrentSchemaVersion, document.SchemaVersion);
            Assert.Equal("test-version", document.ToolVersion);
            Assert.Equal("nessus_xml", document.Source);
            Assert.Equal("10.8", document.SourceVersion);
            Assert.True(document.IsComplete);
            Assert.Equal(Path.GetFileName(path), document.Input.FileName);
            Assert.Equal(new FileInfo(path).Length, document.Input.SizeBytes);
            Assert.Equal(
                Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))),
                document.Input.Sha256);
            Assert.Null(Assert.Single(document.Endpoints).Hostname);
            Assert.Single(document.Findings);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Import_ObservesCancellationBeforeHashingOrParsingInput()
    {
        var path = TemporaryFile("<NessusClientData_v2><Report /></NessusClientData_v2>");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        try
        {
            Assert.Throws<OperationCanceledException>(() => new PentestImportService().Import(
                RemoteImportFormat.NessusXml,
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

    private static string TemporaryFile(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"portcve-import-{Guid.NewGuid():N}.nessus");
        File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return path;
    }
}
