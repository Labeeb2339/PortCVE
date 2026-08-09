using PortCVE.Remote.Advisories;

namespace PortCVE.Tests;

public sealed class RemoteAdvisoryCatalogTests
{
    [Theory]
    [InlineData("OpenSSH", "9.6p1", "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*")]
    [InlineData("Apache httpd", "2.4.62", "cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*")]
    [InlineData("Apache HTTP Server", "2.4.62", "cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*")]
    public void Resolve_VerifiedExactMappingsProduceVersionedCpe(
        string product,
        string version,
        string expectedCpe)
    {
        var result = new RemoteBannerCpeCatalog().Resolve(
            product,
            version,
            $"Server: {product}/{version}",
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
