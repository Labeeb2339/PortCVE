using PortCVE.Remote;

namespace PortCVE.Tests;

public sealed class RemoteFingerprintParserTests
{
    [Fact]
    public void GreetingParser_ExtractsStrongSshProductAndVersionEvidence()
    {
        var result = RemoteFingerprintParser.AnalyzeGreeting(
            "SSH-2.0-OpenSSH_9.9p1 Debian-3\r\n",
            maximumEvidenceBytes: 1_024);

        var fingerprint = Assert.Single(result.Fingerprints);
        Assert.Equal(RemoteFingerprintKind.Ssh, fingerprint.Kind);
        Assert.Equal(RemoteFingerprintConfidence.ProtocolConfirmed, fingerprint.Confidence);
        Assert.Equal("2.0", fingerprint.Attributes["protocolVersion"]);
        var candidate = Assert.Single(result.ProductCandidates);
        Assert.Equal("OpenSSH", candidate.Product);
        Assert.Equal("9.9p1", candidate.Version);
        Assert.Equal(RemoteProductConfidence.BannerPattern, candidate.Confidence);
        Assert.Equal("passive-greeting", candidate.Source);
    }

    [Theory]
    [InlineData("220 ftp.example FTP server (ProFTPD 1.3.8) ready", "ftp", "ProFTPD", "1.3.8")]
    [InlineData("220 mail.example ESMTP Exim 4.98 ready", "smtp", "Exim", "4.98")]
    [InlineData("+OK Dovecot 2.3.21 POP3 ready", "pop3", "Dovecot", "2.3.21")]
    [InlineData("* OK Dovecot 2.3.21 IMAP ready", "imap", "Dovecot", "2.3.21")]
    public void GreetingParser_RecognizesOnlyEvidenceBackedServices(
        string banner,
        string service,
        string product,
        string version)
    {
        var result = RemoteFingerprintParser.AnalyzeGreeting(banner, 1_024);

        Assert.Equal(service, Assert.Single(result.Fingerprints).Service);
        var candidate = Assert.Single(result.ProductCandidates);
        Assert.Equal(product, candidate.Product);
        Assert.Equal(version, candidate.Version);
    }

    [Fact]
    public void GreetingParser_DoesNotTurnGenericPortStyleTextIntoAProductClaim()
    {
        var result = RemoteFingerprintParser.AnalyzeGreeting(
            "220 service ready\r\n",
            maximumEvidenceBytes: 1_024);

        var fingerprint = Assert.Single(result.Fingerprints);
        Assert.Equal(RemoteFingerprintKind.Greeting, fingerprint.Kind);
        Assert.Equal("unknown", fingerprint.Service);
        Assert.Empty(result.ProductCandidates);
    }

    [Fact]
    public void GreetingParser_DoesNotChooseBetweenConflictingFtpAndSmtpMarkers()
    {
        var result = RemoteFingerprintParser.AnalyzeGreeting(
            "220 ProFTPD 1.3.8 ESMTP Exim 4.98 ready\r\n",
            maximumEvidenceBytes: 1_024);

        var fingerprint = Assert.Single(result.Fingerprints);
        Assert.Equal(RemoteFingerprintKind.Greeting, fingerprint.Kind);
        Assert.Equal("unknown", fingerprint.Service);
    }

    [Fact]
    public void HttpParser_ExtractsStatusSelectedHeadersAndReportedProducts()
    {
        const string response = "HTTP/1.1 302 Found\r\n"
            + "Server: nginx/1.27.4\r\n"
            + "X-Powered-By: PHP/8.3.10\r\n"
            + "Location: https://elsewhere.example/\r\n"
            + "Set-Cookie: should-not-be-evidence\r\n\r\n"
            + "body-must-not-be-parsed";

        var result = RemoteFingerprintParser.AnalyzeHttpResponse(
            response,
            RemoteFingerprintKind.Http,
            "passive-http-head",
            maximumEvidenceBytes: 2_048);

        var fingerprint = Assert.Single(result.Fingerprints);
        Assert.Equal("302", fingerprint.Attributes["statusCode"]);
        Assert.Equal("true", fingerprint.Attributes["headersComplete"]);
        Assert.Equal("https://elsewhere.example/", fingerprint.Attributes["location"]);
        Assert.DoesNotContain("Set-Cookie", fingerprint.Evidence, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("body-must-not-be-parsed", fingerprint.Evidence, StringComparison.Ordinal);
        Assert.Collection(
            result.ProductCandidates.OrderBy(static candidate => candidate.Product),
            nginx =>
            {
                Assert.Equal("nginx", nginx.Product);
                Assert.Equal("1.27.4", nginx.Version);
                Assert.Equal(RemoteProductConfidence.HeaderReported, nginx.Confidence);
            },
            php =>
            {
                Assert.Equal("PHP", php.Product);
                Assert.Equal("8.3.10", php.Version);
                Assert.Equal(RemoteProductConfidence.HeaderReported, php.Confidence);
            });
    }

    [Fact]
    public void HttpParser_RejectsMalformedOrNonHttpResponses()
    {
        var result = RemoteFingerprintParser.AnalyzeHttpResponse(
            "SSH-2.0-OpenSSH_9.9\r\nServer: nginx/1.2.3\r\n\r\n",
            RemoteFingerprintKind.Http,
            "passive-http-head",
            maximumEvidenceBytes: 1_024);

        Assert.Empty(result.Fingerprints);
        Assert.Empty(result.ProductCandidates);
    }

    [Theory]
    [InlineData("HTTP/9 200 OK\r\nServer: nginx/1.2.3\r\n\r\n")]
    [InlineData("HTTP/1 200 OK\r\nServer: nginx/1.2.3\r\n\r\n")]
    [InlineData("HTTP/2.0 200 OK\r\nServer: nginx/1.2.3\r\n\r\n")]
    [InlineData("HTTP/1.2 200 OK\r\nServer: nginx/1.2.3\r\n\r\n")]
    public void HttpParser_RejectsUnsupportedTextualProtocolVersions(string response)
    {
        var result = RemoteFingerprintParser.AnalyzeHttpResponse(
            response,
            RemoteFingerprintKind.Http,
            "passive-http-head",
            maximumEvidenceBytes: 1_024);

        Assert.Empty(result.Fingerprints);
        Assert.Empty(result.ProductCandidates);
    }

    [Fact]
    public void GreetingParser_DoesNotPromoteAnIncompleteBannerToAProduct()
    {
        var result = RemoteFingerprintParser.AnalyzeGreeting(
            "SSH-2.0-OpenSSH_9.9p1",
            maximumEvidenceBytes: 1_024,
            isComplete: false);

        var fingerprint = Assert.Single(result.Fingerprints);
        Assert.Equal(RemoteFingerprintKind.Greeting, fingerprint.Kind);
        Assert.Equal("false", fingerprint.Attributes["complete"]);
        Assert.Empty(result.ProductCandidates);
    }

    [Fact]
    public void GreetingParser_DoesNotCreateAProductByReplacingInjectedControls()
    {
        var result = RemoteFingerprintParser.AnalyzeGreeting(
            "SSH-2.0-Other OpenSSH\09.9p1\r\n",
            maximumEvidenceBytes: 1_024);

        Assert.Empty(result.ProductCandidates);
    }

    [Fact]
    public void GreetingParser_BindsSshProductOnlyToTheProtocolSoftwareField()
    {
        var result = RemoteFingerprintParser.AnalyzeGreeting(
            "SSH-2.0-Unrelated_1.0 comment OpenSSH_9.9p1\r\n",
            maximumEvidenceBytes: 1_024);

        Assert.Equal(RemoteFingerprintKind.Ssh, Assert.Single(result.Fingerprints).Kind);
        Assert.Empty(result.ProductCandidates);
    }

    [Fact]
    public void GreetingParser_DoesNotMapAProductPatternFromAnUnrelatedProtocol()
    {
        var result = RemoteFingerprintParser.AnalyzeGreeting(
            "220 generic service OpenSSH_9.9p1 ready\r\n",
            maximumEvidenceBytes: 1_024);

        Assert.Equal(RemoteFingerprintKind.Greeting, Assert.Single(result.Fingerprints).Kind);
        Assert.Empty(result.ProductCandidates);
    }
}
