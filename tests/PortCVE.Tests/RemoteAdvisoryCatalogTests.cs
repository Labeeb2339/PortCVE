using PortCVE.Remote.Advisories;

namespace PortCVE.Tests;

public sealed class RemoteAdvisoryCatalogTests
{
    [Theory]
    [InlineData("OpenSSH", "9.6p1", "SSH-2.0-OpenSSH_9.6p1", "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*")]
    [InlineData("Dropbear SSH", "2020.81", "SSH-2.0-dropbear_2020.81", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2020.81:*:*:*:*:*:*:*")]
    [InlineData("ProFTPD", "1.3.8", "220 ProFTPD 1.3.8 Server (fixture) [192.0.2.1]", "cpe:2.3:a:proftpd:proftpd:1.3.8:*:*:*:*:*:*:*")]
    [InlineData("ProFTPD", "1.3.8a", "220 ProFTPD 1.3.8a Server (fixture) [192.0.2.1]", "cpe:2.3:a:proftpd:proftpd:1.3.8a:*:*:*:*:*:*:*")]
    [InlineData("vsftpd", "3.0.3", "220 (vsFTPd 3.0.3)", "cpe:2.3:a:vsftpd_project:vsftpd:3.0.3:*:*:*:*:*:*:*")]
    [InlineData("Exim", "4.98.2", "220 mail.example ESMTP Exim 4.98.2 ready", "cpe:2.3:a:exim:exim:4.98.2:*:*:*:*:*:*:*")]
    [InlineData("Apache httpd", "2.4.62", "Server: Apache/2.4.62", "cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*")]
    [InlineData("Apache HTTP Server", "2.4.62", "Server: Apache/2.4.62", "cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*")]
    public void Resolve_VerifiedExactMappingsProduceVersionedCpe(
        string product,
        string version,
        string evidence,
        string expectedCpe)
    {
        var result = new RemoteBannerCpeCatalog().Resolve(
            product,
            version,
            evidence,
            RemoteAdvisoryConfidence.Strong);

        Assert.True(result.IsResolved);
        Assert.Equal(expectedCpe, result.Cpe23Uri);
        Assert.Null(result.Diagnostic);
        Assert.Contains("Official CPE Dictionary", result.MappingSource, StringComparison.Ordinal);
        Assert.Equal(
            RemoteBannerCpeCatalog.Resolution.VerifiedCatalogProvenance,
            result.Provenance);
    }

    [Theory]
    [InlineData("Apache", "2.4.62", "Strong", "cpe_mapping_unverified")]
    [InlineData("nginx", "1.26.2", "Strong", "cpe_mapping_unverified")]
    [InlineData("Apache HTTP Server", "2.4.62-custom", "Strong", "version_not_cpe_safe")]
    [InlineData("OpenSSH", "9.6p1 Ubuntu-3", "Strong", "version_not_cpe_safe")]
    [InlineData("Dropbear SSH", "2020.81-test", "Strong", "version_not_cpe_safe")]
    [InlineData("ProFTPD", "1.3.8rc4", "Strong", "version_not_cpe_safe")]
    [InlineData("vsftpd", "3", "Strong", "version_not_cpe_safe")]
    [InlineData("Exim", "4.98-RC3", "Strong", "version_not_cpe_safe")]
    [InlineData("Exim", "4.98.2+deb12", "Strong", "version_not_cpe_safe")]
    [InlineData("OpenSSH", "9.6p1", "Heuristic", "identity_confidence_insufficient")]
    [InlineData("OpenSSH", "9.6p1", "Unresolved", "identity_confidence_insufficient")]
    public void Resolve_UncertainOrAmbiguousIdentityRemainsUnresolved(
        string product,
        string version,
        string confidence,
        string expectedCode)
    {
        var result = new RemoteBannerCpeCatalog().Resolve(
            product,
            version,
            "remote banner",
            Enum.Parse<RemoteAdvisoryConfidence>(confidence));

        Assert.False(result.IsResolved);
        Assert.Null(result.Cpe23Uri);
        Assert.Equal(expectedCode, result.Diagnostic?.Code);
    }
}
