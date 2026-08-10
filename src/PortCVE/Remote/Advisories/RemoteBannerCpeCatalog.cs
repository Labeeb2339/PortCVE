using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PortCVE.Remote.Advisories;

internal sealed partial class RemoteBannerCpeCatalog
{
    private const string OfficialDictionarySource =
        "NVD Official CPE Dictionary (CPE API 2.0 vendor/product mapping)";

    private static readonly IReadOnlyDictionary<string, CatalogEntry> Entries =
        new Dictionary<string, CatalogEntry>(StringComparer.OrdinalIgnoreCase)
        {
            // The vendor/product pairs below were checked against the NVD CPE API 2.0.
            // Deliberately do not add broad names such as "Apache" or ambiguous nginx
            // vendor mappings. An absent entry is safer than an invented CPE identity.
            ["openssh"] = new("openbsd", "openssh", CpeVersionStyle.OpenSshPortable),
            ["dropbear ssh"] = new(
                "dropbear_ssh_project",
                "dropbear_ssh",
                CpeVersionStyle.Plain),
            ["proftpd"] = new("proftpd", "proftpd", CpeVersionStyle.ProFtpdStable),
            ["vsftpd"] = new("vsftpd_project", "vsftpd", CpeVersionStyle.Plain),
            ["exim"] = new("exim", "exim", CpeVersionStyle.Plain),
            ["apache httpd"] = new("apache", "http_server", CpeVersionStyle.Plain),
            ["apache http server"] = new("apache", "http_server", CpeVersionStyle.Plain),
        };

    internal Resolution Resolve(
        string? product,
        string? version,
        string? evidence,
        RemoteAdvisoryConfidence confidence)
    {
        var normalizedProduct = product?.Trim();
        var normalizedVersion = version?.Trim();
        if (string.IsNullOrEmpty(normalizedProduct) ||
            string.IsNullOrEmpty(normalizedVersion) ||
            string.IsNullOrWhiteSpace(evidence))
        {
            return Resolution.Unresolved(
                normalizedProduct,
                normalizedVersion,
                evidence,
                confidence,
                "identity_incomplete",
                "Product, version, and banner evidence are required.");
        }

        if (confidence is not (RemoteAdvisoryConfidence.Exact or RemoteAdvisoryConfidence.Strong))
        {
            return Resolution.Unresolved(
                normalizedProduct,
                normalizedVersion,
                evidence,
                confidence,
                "identity_confidence_insufficient",
                "Only exact or strong banner identities can be mapped to a CPE.");
        }

        if (!Entries.TryGetValue(normalizedProduct, out var entry))
        {
            return Resolution.Unresolved(
                normalizedProduct,
                normalizedVersion,
                evidence,
                confidence,
                "cpe_mapping_unverified",
                "No verified vendor/product CPE mapping exists for this banner identity.");
        }

        if (normalizedVersion.Length > 64)
        {
            return Resolution.Unresolved(
                normalizedProduct,
                normalizedVersion,
                evidence,
                confidence,
                "version_not_cpe_safe",
                "The observed version is not an exact, safely representable CPE version component.");
        }

        string cpeVersion;
        string cpeUpdate;
        if (entry.VersionStyle == CpeVersionStyle.OpenSshPortable)
        {
            var match = OpenSshPortableVersionRegex().Match(normalizedVersion);
            if (!match.Success)
            {
                return Resolution.Unresolved(
                    normalizedProduct,
                    normalizedVersion,
                    evidence,
                    confidence,
                    "version_not_cpe_safe",
                    "The OpenSSH version could not be bound to the NVD dictionary's version/update components.");
            }

            cpeVersion = match.Groups["version"].Value;
            cpeUpdate = $"p{match.Groups["patch"].Value}";
        }
        else if (entry.VersionStyle == CpeVersionStyle.ProFtpdStable)
        {
            if (!ProFtpdStableVersionRegex().IsMatch(normalizedVersion))
            {
                return Resolution.Unresolved(
                    normalizedProduct,
                    normalizedVersion,
                    evidence,
                    confidence,
                    "version_not_cpe_safe",
                    "The ProFTPD version was not a dotted stable release supported by this catalog mapping.");
            }

            // The Official CPE Dictionary represents stable patch-letter
            // releases such as 1.3.8a in the version component itself.
            cpeVersion = normalizedVersion.ToLowerInvariant();
            cpeUpdate = "*";
        }
        else
        {
            if (!DottedNumericVersionRegex().IsMatch(normalizedVersion))
            {
                return Resolution.Unresolved(
                    normalizedProduct,
                    normalizedVersion,
                    evidence,
                    confidence,
                    "version_not_cpe_safe",
                    "The observed version was not a dotted numeric version supported by this catalog mapping.");
            }

            cpeVersion = normalizedVersion.ToLowerInvariant();
            cpeUpdate = "*";
        }

        var cpe = $"cpe:2.3:a:{entry.Vendor}:{entry.Product}:{cpeVersion}:{cpeUpdate}:*:*:*:*:*:*";
        return Resolution.Resolved(
            normalizedProduct,
            normalizedVersion,
            evidence!,
            confidence,
            cpe,
            OfficialDictionarySource);
    }

    [GeneratedRegex("^[0-9]+(?:\\.[0-9]+)+$", RegexOptions.CultureInvariant)]
    private static partial Regex DottedNumericVersionRegex();

    [GeneratedRegex("^(?<version>[0-9]+(?:\\.[0-9]+)+)p(?<patch>[0-9]+)$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex OpenSshPortableVersionRegex();

    [GeneratedRegex("^[0-9]+(?:\\.[0-9]+)+[a-z]?$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ProFtpdStableVersionRegex();

    private sealed record CatalogEntry(
        string Vendor,
        string Product,
        CpeVersionStyle VersionStyle);

    private enum CpeVersionStyle
    {
        Plain,
        OpenSshPortable,
        ProFtpdStable,
    }

    internal sealed class Resolution
    {
        internal const string VerifiedCatalogProvenance = "verified_banner_cpe_catalog_v1";

        private Resolution(
            bool isResolved,
            string? observedProduct,
            string? observedVersion,
            string? evidenceSha256,
            RemoteAdvisoryConfidence confidence,
            string? cpe23Uri,
            string mappingSource,
            RemoteAdvisoryDiagnostic? diagnostic)
        {
            IsResolved = isResolved;
            ObservedProduct = observedProduct;
            ObservedVersion = observedVersion;
            EvidenceSha256 = evidenceSha256;
            Confidence = confidence;
            Cpe23Uri = cpe23Uri;
            MappingSource = mappingSource;
            Diagnostic = diagnostic;
        }

        internal bool IsResolved { get; }
        internal string? ObservedProduct { get; }
        internal string? ObservedVersion { get; }
        internal string? EvidenceSha256 { get; }
        internal RemoteAdvisoryConfidence Confidence { get; }
        internal string? Cpe23Uri { get; }
        internal string MappingSource { get; }
        internal string Provenance => VerifiedCatalogProvenance;
        internal RemoteAdvisoryDiagnostic? Diagnostic { get; }

        internal bool MatchesIdentity(RemoteAdvisoryIdentity identity) =>
            IsResolved &&
            string.Equals(ObservedProduct, identity.Product.Trim(), StringComparison.OrdinalIgnoreCase) &&
            string.Equals(ObservedVersion, identity.Version.Trim(), StringComparison.OrdinalIgnoreCase) &&
            Confidence == identity.Confidence &&
            string.Equals(
                EvidenceSha256,
                HashEvidence(identity.Evidence),
                StringComparison.Ordinal);

        internal static Resolution Resolved(
            string observedProduct,
            string observedVersion,
            string evidence,
            RemoteAdvisoryConfidence confidence,
            string cpe23Uri,
            string mappingSource) =>
            new(
                true,
                observedProduct,
                observedVersion,
                HashEvidence(evidence),
                confidence,
                cpe23Uri,
                mappingSource,
                null);

        internal static Resolution Unresolved(
            string? observedProduct,
            string? observedVersion,
            string? evidence,
            RemoteAdvisoryConfidence confidence,
            string code,
            string message) =>
            new(
                false,
                observedProduct,
                observedVersion,
                string.IsNullOrWhiteSpace(evidence) ? null : HashEvidence(evidence),
                confidence,
                null,
                OfficialDictionarySource,
                new(code, message));

        private static string HashEvidence(string evidence) =>
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(evidence.Trim())))
                .ToLowerInvariant();
    }
}
