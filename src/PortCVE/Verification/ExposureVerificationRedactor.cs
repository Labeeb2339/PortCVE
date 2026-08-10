using PortCVE.Domain;
using PortCVE.Remote.Imports;
using PortCVE.Snapshots;
using System.Text.RegularExpressions;

namespace PortCVE.Verification;

internal static class ExposureVerificationRedactor
{
    private static readonly string RedactedSha256 = new('0', 64);

    internal static ExposureVerificationReport Redact(ExposureVerificationReport report)
    {
        var outsideAliases = report.Endpoints
            .SelectMany(static endpoint => endpoint.OutsideObservations)
            .SelectMany(static observation => new[] { observation.Target, observation.Hostname });
        var localAliases = report.Endpoints
            .SelectMany(static endpoint => endpoint.LocalListeners)
            .Select(static listener => listener.LocalAddress);
        var privateAliases = outsideAliases
            .Concat(localAliases)
            .Concat(report.PrivateRedactionAliases)
            .Append(report.Association.ImportedTarget)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(static value => value.Length)
            .ToArray();
        var aliasRedactor = AliasRedactor.Create(privateAliases);

        return report with
        {
            PrivacyMode = VerificationPrivacyMode.Reduced,
            Association = report.Association with
            {
                ImportedTarget = "target-1",
                Vantage = "operator-labeled-vantage",
            },
            Inputs = report.Inputs.Select(input => input with
            {
                FileName = input.FileName is null ? null : $"{input.Source.ToString().ToLowerInvariant()}-input",
                Sha256 = input.Sha256 is null ? null : RedactedSha256,
            }).ToArray(),
            Endpoints = report.Endpoints.Select(endpoint => RedactEndpoint(endpoint, aliasRedactor)).ToArray(),
            TargetFindings = report.TargetFindings
                .Select(finding => RedactFinding(finding, aliasRedactor))
                .ToArray(),
            Diagnostics = report.Diagnostics.Select(static diagnostic => diagnostic with
            {
                Message = "Diagnostic details redacted; rerun with --include-private to inspect them locally.",
            }).ToArray(),
            PrivateRedactionAliases = [],
        };
    }

    private static VerifiedExposureEndpoint RedactEndpoint(
        VerifiedExposureEndpoint endpoint,
        AliasRedactor aliasRedactor) => endpoint with
        {
            OutsideObservations = endpoint.OutsideObservations.Select(observation => observation with
            {
                Target = "target-1",
                Hostname = null,
                StateReason = observation.StateReason is null ? null : "redacted",
                Service = RedactService(observation.Service, aliasRedactor),
            }).ToArray(),
            LocalListeners = endpoint.LocalListeners.Select(listener => listener with
            {
                LocalAddress = listener.BindScope switch
                {
                    BindScope.Loopback => "loopback",
                    BindScope.Wildcard => "any",
                    BindScope.Interface => "interface",
                    _ => "unknown",
                },
                OwnerIdentity = RedactText(
                    RedactOwnerIdentity(listener.OwnerIdentityStrength, listener.OwnerIdentity),
                    aliasRedactor)!,
                ImageName = RedactText(listener.ImageName, aliasRedactor)!,
                Services = listener.Services.Select(service => RedactText(service, aliasRedactor)!).ToArray(),
                ContainerImages = listener.ContainerImages.Count == 0 ? [] : ["redacted image identity"],
                Limitations = listener.Limitations.Count == 0
                    ? []
                    : ["Listener limitation details were redacted."],
            }).ToArray(),
            Limitations = endpoint.Limitations.Count == 0
            ? []
            : ["Correlation limitations are present; rerun with --include-private for details."],
            Findings = endpoint.Findings.Select(finding => RedactFinding(finding, aliasRedactor)).ToArray(),
        };

    private static ImportedServiceIdentity? RedactService(
        ImportedServiceIdentity? service,
        AliasRedactor aliasRedactor) => service is null ? null : service with
        {
            Name = RedactText(service.Name, aliasRedactor),
            Product = RedactText(service.Product, aliasRedactor),
            Version = RedactText(service.Version, aliasRedactor),
            ExtraInfo = RedactText(service.ExtraInfo, aliasRedactor),
            Cpes = service.Cpes.Select(cpe => RedactText(cpe, aliasRedactor)!).ToArray(),
            EvidenceSource = RedactText(service.EvidenceSource, aliasRedactor)!,
        };

    private static VerificationFindingGroup RedactFinding(
        VerificationFindingGroup finding,
        AliasRedactor aliasRedactor) => finding with
        {
            FindingGroupId = IsCveGroupId(finding.FindingGroupId)
                ? finding.FindingGroupId
                : RedactText(finding.FindingGroupId, aliasRedactor)!,
            Title = RedactText(finding.Title, aliasRedactor)!,
            AdvisoryIds = finding.AdvisoryIds
                .Select(advisory => IsCveId(advisory) ? advisory : RedactText(advisory, aliasRedactor)!)
                .ToArray(),
            Observations = finding.Observations.Select(observation => observation with
            {
                FindingId = RedactText(observation.FindingId, aliasRedactor)!,
                Title = RedactText(observation.Title, aliasRedactor)!,
                AdvisoryIds = observation.AdvisoryIds
                    .Select(advisory => IsCveId(advisory) ? advisory : RedactText(advisory, aliasRedactor)!)
                    .ToArray(),
                Matcher = RedactText(observation.Matcher, aliasRedactor),
                SourceRecordSha256 = RedactedSha256,
            }).ToArray(),
        };

    private static string RedactOwnerIdentity(OwnerIdentityStrength strength, string value) => strength switch
    {
        OwnerIdentityStrength.Sha256 => "sha256:redacted",
        OwnerIdentityStrength.ContainerImage => "container-image-set:redacted",
        OwnerIdentityStrength.Unknown => "unknown",
        _ => value,
    };

    private static string? RedactText(string? value, AliasRedactor aliasRedactor) =>
        aliasRedactor.Redact(value);

    private static bool IsCveGroupId(string value) => value.StartsWith("cve:", StringComparison.Ordinal)
        && IsCveId(value[4..]);

    private static bool IsCveId(string value)
    {
        if (!value.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var separator = value.IndexOf('-', 4);
        if (separator != 8 || value.Length - separator - 1 < 4)
        {
            return false;
        }

        return value.AsSpan(4, 4).IndexOfAnyExceptInRange('0', '9') < 0
            && value.AsSpan(separator + 1).IndexOfAnyExceptInRange('0', '9') < 0;
    }

    private sealed class AliasRedactor
    {
        private const int MaximumAliasCount = 32;
        private readonly Regex? shortAliasPattern;
        private readonly Regex? longAliasPattern;
        private readonly bool redactEverything;

        private AliasRedactor(Regex? shortAliasPattern, Regex? longAliasPattern, bool redactEverything)
        {
            this.shortAliasPattern = shortAliasPattern;
            this.longAliasPattern = longAliasPattern;
            this.redactEverything = redactEverything;
        }

        internal static AliasRedactor Create(IEnumerable<string> aliases)
        {
            var distinct = aliases.Where(static alias => !string.IsNullOrWhiteSpace(alias))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(MaximumAliasCount + 1)
                .ToArray();
            if (distinct.Length > MaximumAliasCount)
            {
                return new(null, null, true);
            }

            return new(
                CreatePattern(distinct.Where(static alias => alias.Length < 3)),
                CreatePattern(distinct.Where(static alias => alias.Length >= 3)),
                false);
        }

        internal string? Redact(string? value)
        {
            if (value is null)
            {
                return null;
            }

            if (redactEverything || shortAliasPattern?.IsMatch(value) == true)
            {
                return "redacted";
            }

            return longAliasPattern?.Replace(value, "x") ?? value;
        }

        private static Regex? CreatePattern(IEnumerable<string> aliases)
        {
            var values = aliases.OrderByDescending(static alias => alias.Length)
                .Select(Regex.Escape)
                .ToArray();
            return values.Length == 0
                ? null
                : new(
                    string.Join('|', values),
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
                    TimeSpan.FromMilliseconds(250));
        }
    }
}
