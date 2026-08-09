using System.Text;
using System.Xml;
using PortCVE.Remote.Imports;

namespace PortCVE.Tests;

public sealed class RemoteImportTests
{
    [Fact]
    public void NmapXml_ImportsEvidenceWithoutTrustingPortTableAsStrongIdentity()
    {
        const string xml = """
            <?xml version="1.0"?>
            <nmaprun scanner="nmap" version="7.98" xmloutputversion="1.05">
              <host>
                <address addr="192.0.2.10" addrtype="ipv4" />
                <hostnames><hostname name="fixture.example" /></hostnames>
                <ports>
                  <port protocol="tcp" portid="22">
                    <state state="open" reason="syn-ack" />
                    <service name="ssh" product="OpenSSH" version="9.6p1" method="probed" conf="10">
                      <cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>
                    </service>
                    <script id="ssh-hostkey" output="fingerprint only" />
                  </port>
                  <port protocol="tcp" portid="80">
                    <state state="open" reason="syn-ack" />
                    <service name="http" method="table" conf="3" />
                  </port>
                </ports>
              </host>
              <runstats><finished exit="success" /></runstats>
            </nmaprun>
            """;

        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(xml));
        var report = NmapXmlImporter.Import(stream);

        Assert.True(report.IsComplete);
        Assert.Equal("7.98", report.SourceVersion);
        Assert.Equal(2, report.Endpoints.Count);
        Assert.Equal(ImportedEvidenceStrength.Strong, report.Endpoints[0].Service!.EvidenceStrength);
        Assert.Equal(ImportedEvidenceStrength.Weak, report.Endpoints[1].Service!.EvidenceStrength);
        var script = Assert.Single(report.Findings);
        Assert.Equal(ImportedClaimStatus.ImportedMatch, script.ClaimStatus);
        Assert.Equal(ImportedEvidenceStrength.Unresolved, script.EvidenceStrength);
        Assert.Null(script.Summary);
    }

    [Fact]
    public void NmapXml_RejectsDtdAndIncompleteRunIsNotClean()
    {
        const string dtd = "<!DOCTYPE nmaprun [<!ENTITY x 'boom'>]><nmaprun>&x;</nmaprun>";
        using var dtdStream = new MemoryStream(Encoding.UTF8.GetBytes(dtd));
        Assert.Throws<XmlException>(() => NmapXmlImporter.Import(dtdStream));

        using var incomplete = new MemoryStream(Encoding.UTF8.GetBytes("<nmaprun><host /></nmaprun>"));
        var report = NmapXmlImporter.Import(incomplete);
        Assert.False(report.IsComplete);
        Assert.Contains(report.Diagnostics, static item => item.Code == "nmap_scan_incomplete");
    }

    [Fact]
    public void NucleiJsonl_ImportsNormalizedMatchAndNeverRetainsRawRequest()
    {
        const string jsonl = """
            {"template-id":"tls-version","info":{"name":"TLS version observation","severity":"medium","classification":{"cve-id":["CVE-2020-0001"]},"reference":["https://example.invalid/advisory"]},"host":"https://192.0.2.10","matched-at":"https://192.0.2.10:443","port":"443","scheme":"https","matcher-name":"tls-legacy","extracted-results":["TLS 1.0"],"request":"Authorization: secret","response":"secret body","curl-command":"curl --token secret"}
            """;

        using var input = Utf8Stream(jsonl);
        var report = NucleiJsonlImporter.Import(input);

        var finding = Assert.Single(report.Findings);
        Assert.Equal("tls-version", finding.FindingId);
        Assert.Equal("medium", finding.Severity);
        Assert.Equal(443, finding.Port);
        Assert.Equal(["CVE-2020-0001"], finding.AdvisoryIds);
        Assert.Null(finding.Summary);
        var serialized = System.Text.Json.JsonSerializer.Serialize(report);
        Assert.DoesNotContain("Authorization", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("secret body", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("curl --token", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("TLS 1.0", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public void NucleiJsonl_StrictRejectsMalformedAndLenientMarksIncomplete()
    {
        using var malformed = Utf8Stream("{not-json}");
        Assert.Throws<InvalidDataException>(() => NucleiJsonlImporter.Import(malformed));

        using var mixed = Utf8Stream(
            "{not-json}\n{\"template-id\":\"x\",\"info\":{\"name\":\"x\"},\"host\":\"127.0.0.1\"}");
        var report = NucleiJsonlImporter.Import(
            mixed,
            strict: false);
        Assert.False(report.IsComplete);
        Assert.Single(report.Findings);
        Assert.Single(report.Diagnostics);
    }

    [Fact]
    public void NucleiJsonl_DefaultNormalizationRemovesSecretsAndCanonicalizesUrls()
    {
        const string redactionMarker = "DoNotPublish-Access-Token-48291";
        var jsonl = $$"""
            {"template-id":"http-token-check","info":{"name":"https://reader:password@title.invalid/?access_token={{redactionMarker}}#private","severity":"high","classification":{"cve-id":["CVE-2024-12345","not-an-advisory"]},"reference":["https://reader:password@example.invalid/advisory/token/{{redactionMarker}}?access_token={{redactionMarker}}#private"]},"matched-at":"https://alice:password@192.0.2.10:8443/reset/{{redactionMarker}}?access_token={{redactionMarker}}#private","port":8443,"scheme":"https","matcher-name":"body-check","extracted-results":["username=admin; password={{redactionMarker}}"],"request":"Authorization: Bearer {{redactionMarker}}","response":"Set-Cookie: session={{redactionMarker}}","curl-command":"curl -H 'Authorization: {{redactionMarker}}'","template":"raw {{redactionMarker}}","template-encoded":"{{redactionMarker}}","template-url":"https://templates.invalid/{{redactionMarker}}"}
            """;

        using var input = Utf8Stream(jsonl);
        var finding = Assert.Single(NucleiJsonlImporter.Import(input).Findings);

        Assert.Equal("https://192.0.2.10:8443", finding.Target);
        Assert.Equal("http-token-check", finding.Title);
        Assert.Equal(["CVE-2024-12345"], finding.AdvisoryIds);
        Assert.Equal(["https://example.invalid/advisory/token"], finding.References);
        Assert.Null(finding.Summary);
        var serialized = System.Text.Json.JsonSerializer.Serialize(finding);
        Assert.DoesNotContain(redactionMarker, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("alice", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("password", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("access_token", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("Authorization", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("Set-Cookie", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("curl", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("templates.invalid", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public void NmapXml_DropsNseOutputAndRejectsForgedCompletion()
    {
        const string redactionMarker = "DoNotPublish-NSE-Secret-48291";
        var xml = $$"""
            <nmaprun version="7.98">
              <host>
                <address addr="192.0.2.10" addrtype="ipv4" />
                <ports><port protocol="tcp" portid="80">
                  <script id="http-headers" output="Authorization: Bearer {{redactionMarker}}" />
                </port></ports>
                <finished exit="success" />
              </host>
            </nmaprun>
            """;

        using var input = Utf8Stream(xml);
        var report = NmapXmlImporter.Import(input);

        Assert.False(report.IsComplete);
        var finding = Assert.Single(report.Findings);
        Assert.Equal("http-headers", finding.FindingId);
        Assert.Null(finding.Summary);
        Assert.DoesNotContain(
            redactionMarker,
            System.Text.Json.JsonSerializer.Serialize(report),
            StringComparison.Ordinal);
    }

    [Fact]
    public void NmapXml_OnlyAcceptsCanonicalHostnamePortAndFinishedPaths()
    {
        const string xml = """
            <nmaprun xmlns:fake="urn:fake">
              <host>
                <address addr="192.0.2.10" addrtype="ipv4" />
                <hostnames>
                  <wrapper><hostname name="spoofed.invalid" /></wrapper>
                  <hostname name="canonical.example" />
                </hostnames>
                <wrapper><port protocol="tcp" portid="22" /></wrapper>
                <ports>
                  <wrapper><port protocol="tcp" portid="23" /></wrapper>
                  <port protocol="tcp" portid="443"><state state="open" /></port>
                </ports>
              </host>
              <wrapper><finished exit="success" /></wrapper>
              <runstats><wrapper><finished exit="success" /></wrapper><fake:finished exit="success" /></runstats>
            </nmaprun>
            """;

        using var input = Utf8Stream(xml);
        var report = NmapXmlImporter.Import(input);

        var endpoint = Assert.Single(report.Endpoints);
        Assert.Equal(443, endpoint.Port);
        Assert.Equal("canonical.example", endpoint.Hostname);
        Assert.False(report.IsComplete);
    }

    [Fact]
    public void NmapXml_DropsSensitiveStateReasonVersionAndCpeText()
    {
        const string xml = """
            <nmaprun version="password=source-version-secret">
              <host>
                <address addr="192.0.2.10" addrtype="ipv4" />
                <ports>
                  <port protocol="tcp" portid="443">
                    <state state="password=state-secret" reason="token=reason-secret" />
                    <service name="https" method="probed" conf="10">
                      <cpe>cpe:/a:vendor:product:password=cpe-secret</cpe>
                    </service>
                  </port>
                </ports>
              </host>
              <runstats><finished exit="success" /></runstats>
            </nmaprun>
            """;

        using var input = Utf8Stream(xml);
        var report = NmapXmlImporter.Import(input);

        Assert.True(report.IsComplete);
        Assert.Null(report.SourceVersion);
        var endpoint = Assert.Single(report.Endpoints);
        Assert.Equal("unknown", endpoint.State);
        Assert.Null(endpoint.StateReason);
        Assert.Empty(endpoint.Service!.Cpes);
        var serialized = System.Text.Json.JsonSerializer.Serialize(report);
        Assert.DoesNotContain("source-version-secret", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("state-secret", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("reason-secret", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("cpe-secret", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public void NmapXml_EnforcesDepthAndHostCardinality()
    {
        var deep = $"<nmaprun>{string.Concat(Enumerable.Repeat("<x>", 33))}{string.Concat(Enumerable.Repeat("</x>", 33))}</nmaprun>";
        using var deepInput = Utf8Stream(deep);
        var depthError = Assert.Throws<InvalidDataException>(() => NmapXmlImporter.Import(deepInput));
        Assert.Contains("depth", depthError.Message, StringComparison.OrdinalIgnoreCase);

        var manyHosts = new StringBuilder("<nmaprun>");
        for (var index = 0; index < 4097; index++)
        {
            manyHosts.Append("<host />");
        }

        manyHosts.Append("</nmaprun>");
        using var cardinalityInput = Utf8Stream(manyHosts.ToString());
        var cardinalityError = Assert.Throws<InvalidDataException>(() => NmapXmlImporter.Import(cardinalityInput));
        Assert.Contains("4096", cardinalityError.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NucleiJsonl_OversizedRecordIsRejectedBeforeHugeLineIsMaterialized()
    {
        using var input = new RepeatingByteStream(256L * 1024 * 1024, (byte)'x');

        var exception = Assert.Throws<InvalidDataException>(() => NucleiJsonlImporter.Import(input));

        Assert.Contains("1 MiB", exception.Message, StringComparison.Ordinal);
        Assert.InRange(input.BytesRead, 1024 * 1024 + 1, 2L * 1024 * 1024);
    }

    [Fact]
    public void NucleiJsonl_LenientModeDiscardsOversizedRecordAndContinues()
    {
        var valid = Encoding.UTF8.GetBytes(
            "\n{\"template-id\":\"safe\",\"info\":{\"name\":\"safe\"},\"host\":\"127.0.0.1\"}\n");
        using var input = new MemoryStream(capacity: 1024 * 1024 + valid.Length + 1);
        input.Write(new byte[1024 * 1024 + 1]);
        input.Write(valid);
        input.Position = 0;

        var report = NucleiJsonlImporter.Import(input, strict: false);

        Assert.False(report.IsComplete);
        Assert.Single(report.Diagnostics);
        Assert.Single(report.Findings);
    }

    [Fact]
    public void NucleiJsonl_EnforcesAggregateNormalizedOutputBudget()
    {
        var safeLongPath = string.Join('/', Enumerable.Repeat("docs", 360));
        var references = string.Join(
            ',',
            Enumerable.Range(0, 32).Select(index => $"\"https://reference-{index}.invalid/{safeLongPath}\""));
        var inputBuilder = new StringBuilder();
        for (var index = 0; index < 400; index++)
        {
            inputBuilder.Append(
                $"{{\"template-id\":\"finding-{index}\",\"info\":{{\"name\":\"finding\",\"reference\":[{references}]}},\"host\":\"https://192.0.2.10\"}}\n");
        }

        using var input = Utf8Stream(inputBuilder.ToString());
        var exception = Assert.Throws<InvalidDataException>(() => NucleiJsonlImporter.Import(input));

        Assert.Contains("retained-character", exception.Message, StringComparison.Ordinal);
    }

    private static MemoryStream Utf8Stream(string value) =>
        new(Encoding.UTF8.GetBytes(value), writable: false);

    private sealed class RepeatingByteStream(long length, byte value) : Stream
    {
        private long position;

        public long BytesRead { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => length;

        public override long Position
        {
            get => position;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var remaining = length - position;
            if (remaining <= 0)
            {
                return 0;
            }

            var returned = (int)Math.Min(count, remaining);
            buffer.AsSpan(offset, returned).Fill(value);
            position += returned;
            BytesRead += returned;
            return returned;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
