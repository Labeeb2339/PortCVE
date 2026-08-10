using System.Text;
using System.Text.Json;
using System.Xml;
using PortCVE.Remote.Imports;

namespace PortCVE.Tests;

public sealed class NessusXmlImporterTests
{
    [Fact]
    public void Import_NormalizesFindingsAndOmitsRawOutputAndCredentialProperties()
    {
        const string omittedValue = "fixture-value-not-retained";
        var xml = $$"""
            <?xml version="1.0"?>
            <NessusClientData_v2 version="10.8">
              <Report name="fixture">
                <ReportHost name="fallback.example">
                  <HostProperties>
                    <tag name="host-ip">192.0.2.10</tag>
                    <tag name="host-fqdn">fixture.example</tag>
                    <tag name="Credentialed_Scan">true</tag>
                    <tag name="ssh-auth-meth">password={{omittedValue}}</tag>
                  </HostProperties>
                  <ReportItem port="443" svc_name="https" protocol="tcp" severity="3"
                              pluginID="10001" pluginName="TLS configuration finding">
                    <cve>CVE-2024-12345</cve>
                    <cve>CVE-2024-12345</cve>
                    <plugin_output>Authorization: Bearer {{omittedValue}}</plugin_output>
                  </ReportItem>
                  <ReportItem port="0" svc_name="general" protocol="tcp" severity="0"
                              pluginID="19506" pluginName="Nessus Scan Information">
                    <plugin_output>credential={{omittedValue}}</plugin_output>
                  </ReportItem>
                </ReportHost>
              </Report>
            </NessusClientData_v2>
            """;

        using var input = Utf8Stream(xml);
        var report = NessusXmlImporter.Import(input);

        Assert.True(report.IsComplete);
        Assert.Equal("nessus_xml", report.Source);
        Assert.Equal("10.8", report.SourceVersion);
        var endpoint = Assert.Single(report.Endpoints);
        Assert.Equal("192.0.2.10", endpoint.Target);
        Assert.Equal("fixture.example", endpoint.Hostname);
        Assert.Equal("tcp", endpoint.Protocol);
        Assert.Equal(443, endpoint.Port);
        Assert.Equal("reported", endpoint.State);
        Assert.Equal("https", endpoint.Service!.Name);
        Assert.Equal(ImportedEvidenceStrength.Weak, endpoint.Service.EvidenceStrength);

        Assert.Equal(2, report.Findings.Count);
        var finding = Assert.Single(report.Findings, static item => item.FindingId == "10001");
        Assert.Equal("TLS configuration finding", finding.Title);
        Assert.Equal("high", finding.Severity);
        Assert.Equal(443, finding.Port);
        Assert.Equal("tcp", finding.Protocol);
        Assert.Equal(["CVE-2024-12345"], finding.AdvisoryIds);
        Assert.Equal(ImportedClaimStatus.ImportedMatch, finding.ClaimStatus);
        Assert.Equal(ImportedEvidenceStrength.Unresolved, finding.EvidenceStrength);
        var hostFinding = Assert.Single(report.Findings, static item => item.FindingId == "19506");
        Assert.Null(hostFinding.Port);
        Assert.Null(hostFinding.Protocol);
        var hostAlias = Assert.Single(report.PrivateHostAliases);
        Assert.Equal("192.0.2.10", hostAlias.Target);
        Assert.Equal("fixture.example", hostAlias.Hostname);

        var serialized = JsonSerializer.Serialize(report);
        Assert.DoesNotContain(omittedValue, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("plugin_output", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("Credentialed_Scan", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("ssh-auth-meth", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("privateHostAliases", serialized, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Import_RejectsDtdAndOnlyAcceptsCanonicalEvidencePaths()
    {
        const string dtd = "<!DOCTYPE NessusClientData_v2 [<!ENTITY x 'boom'>]><NessusClientData_v2>&x;</NessusClientData_v2>";
        using var dtdInput = Utf8Stream(dtd);
        Assert.Throws<XmlException>(() => NessusXmlImporter.Import(dtdInput));

        const string xml = """
            <NessusClientData_v2 xmlns:fake="urn:fake">
              <Report name="fixture">
                <ReportHost name="192.0.2.10">
                  <wrapper>
                    <ReportItem port="22" protocol="tcp" severity="4" pluginID="99999" pluginName="forged" />
                  </wrapper>
                  <fake:ReportItem port="23" protocol="tcp" severity="4" pluginID="99998" pluginName="namespaced" />
                  <ReportItem port="443" protocol="tcp" severity="2" pluginID="10002" pluginName="canonical">
                    <wrapper><cve>CVE-2024-99999</cve></wrapper>
                    <cve>not-a-cve</cve>
                    <cve>CVE-2024-12345</cve>
                  </ReportItem>
                </ReportHost>
              </Report>
            </NessusClientData_v2>
            """;

        using var input = Utf8Stream(xml);
        var report = NessusXmlImporter.Import(input);

        Assert.False(report.IsComplete);
        var finding = Assert.Single(report.Findings);
        Assert.Equal("10002", finding.FindingId);
        Assert.Equal(["CVE-2024-12345"], finding.AdvisoryIds);
        Assert.Contains(report.Diagnostics, static item => item.Code == "nessus_structure_ignored");
        Assert.Contains(report.Diagnostics, static item => item.Code == "nessus_cve_invalid");
    }

    [Fact]
    public void Import_DroppedMalformedItemsAndHostsMakeEvidenceIncomplete()
    {
        const string xml = """
            <NessusClientData_v2>
              <Report name="fixture">
                <ReportHost name="192.0.2.10">
                  <ReportItem port="443" protocol="tcp" severity="unexpected" pluginID="10003" pluginName="retained" />
                  <ReportItem port="70000" protocol="tcp" severity="3" pluginID="10004" pluginName="bad port" />
                  <ReportItem port="443" protocol="tcp" severity="3" pluginName="missing plugin" />
                </ReportHost>
                <ReportHost>
                  <ReportItem port="80" protocol="tcp" severity="2" pluginID="10005" pluginName="no safe target" />
                </ReportHost>
              </Report>
            </NessusClientData_v2>
            """;

        using var input = Utf8Stream(xml);
        var report = NessusXmlImporter.Import(input);

        Assert.False(report.IsComplete);
        var finding = Assert.Single(report.Findings);
        Assert.Equal("10003", finding.FindingId);
        Assert.Equal("unknown", finding.Severity);
        Assert.Contains(report.Diagnostics, static item => item.Code == "nessus_severity_invalid");
        Assert.Contains(report.Diagnostics, static item => item.Code == "nessus_item_invalid");
        Assert.Contains(report.Diagnostics, static item => item.Code == "nessus_host_without_target");
    }

    [Fact]
    public void Import_EnforcesDepthHostAndRetainedTextBounds()
    {
        var deep = $"<NessusClientData_v2>{string.Concat(Enumerable.Repeat("<x>", 33))}{string.Concat(Enumerable.Repeat("</x>", 33))}</NessusClientData_v2>";
        using var deepInput = Utf8Stream(deep);
        var depthError = Assert.Throws<InvalidDataException>(() => NessusXmlImporter.Import(deepInput));
        Assert.Contains("depth", depthError.Message, StringComparison.OrdinalIgnoreCase);

        var hosts = new StringBuilder("<NessusClientData_v2><Report>");
        for (var index = 0; index < 4097; index++)
        {
            hosts.Append($"<ReportHost name=\"host-{index}.example\" />");
        }

        hosts.Append("</Report></NessusClientData_v2>");
        using var hostsInput = Utf8Stream(hosts.ToString());
        var hostError = Assert.Throws<InvalidDataException>(() => NessusXmlImporter.Import(hostsInput));
        Assert.Contains("4096", hostError.Message, StringComparison.Ordinal);

        var longTitle = new string('A', 512);
        var retained = new StringBuilder("<NessusClientData_v2><Report><ReportHost name=\"192.0.2.10\">");
        for (var index = 0; index < 15000; index++)
        {
            retained.Append(
                $"<ReportItem port=\"443\" protocol=\"tcp\" severity=\"3\" pluginID=\"{100000 + index}\" pluginName=\"{longTitle}\" />");
        }

        retained.Append("</ReportHost></Report></NessusClientData_v2>");
        using var retainedInput = Utf8Stream(retained.ToString());
        var retainedError = Assert.Throws<InvalidDataException>(() => NessusXmlImporter.Import(retainedInput));
        Assert.Contains("retained-character", retainedError.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Import_ObservesCancellation()
    {
        using var input = Utf8Stream("<NessusClientData_v2><Report /></NessusClientData_v2>");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.Throws<OperationCanceledException>(() =>
            NessusXmlImporter.Import(input, cancellation.Token));
    }

    private static MemoryStream Utf8Stream(string value) =>
        new(Encoding.UTF8.GetBytes(value), writable: false);
}
