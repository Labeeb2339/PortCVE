using PortCVE.Remote.Advisories;

namespace PortCVE.Remote;

internal static class RemoteAuditRedactor
{
    private static readonly HashSet<string> SafeFingerprintAttributes = new(StringComparer.Ordinal)
    {
        "httpVersion",
        "protocolVersion",
        "statusCode",
        "tlsProtocol",
    };

    internal static RemoteAuditReport Redact(RemoteAuditReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var targetAliases = report.Hosts
            .Select(static host => host.Target)
            .Distinct(StringComparer.Ordinal)
            .Select((target, index) => (target, alias: $"target-{index + 1:000}"))
            .ToDictionary(static item => item.target, static item => item.alias, StringComparer.Ordinal);
        var addressAliases = report.Hosts
            .SelectMany(static host => host.ResolvedAddresses)
            .Concat(report.Hosts.SelectMany(static host => host.Ports.Select(static port => port.Address)))
            .Distinct(StringComparer.Ordinal)
            .Select((address, index) => (address, alias: $"address-{index + 1:000}"))
            .ToDictionary(static item => item.address, static item => item.alias, StringComparer.Ordinal);

        var hosts = report.Hosts.Select(host => new RemoteHostReport(
            Alias(targetAliases, host.Target, "target-redacted"),
            host.ResolvedAddresses.Select(address => Alias(addressAliases, address, "address-redacted")).ToArray(),
            host.Ports.Select(port => RedactPort(port, addressAliases)).ToArray(),
            RedactDiagnostics(
                host.Diagnostics,
                "Remote target details were redacted; use the diagnostic code for classification."))).ToArray();

        var assessments = report.AdvisoryAssessments.Select(item => item with
        {
            Target = Alias(targetAliases, item.Target, "target-redacted"),
            Address = Alias(addressAliases, item.Address, "address-redacted"),
            Evidence = "[redacted]",
            Diagnostics = RedactAdvisoryDiagnostics(
                item.Diagnostics,
                "Remote advisory assessment details were redacted; use the diagnostic code for classification."),
        }).ToArray();
        var advisoryResults = report.AdvisoryResults.Select(result => result with
        {
            Matches = result.Matches.Select(match => match with { Evidence = "[redacted]" }).ToArray(),
            Diagnostics = RedactAdvisoryDiagnostics(
                result.Diagnostics,
                "Advisory provider details were redacted; use the diagnostic code for classification."),
        }).ToArray();

        return report with
        {
            Selector = "redacted",
            Hosts = hosts,
            AdvisoryAssessments = assessments,
            AdvisoryResults = advisoryResults,
            Diagnostics = RedactDiagnostics(
                report.Diagnostics,
                "Remote report details were redacted; use the diagnostic code for classification."),
        };
    }

    private static RemotePortResult RedactPort(
        RemotePortResult port,
        IReadOnlyDictionary<string, string> addressAliases) =>
        port with
        {
            Address = Alias(addressAliases, port.Address, "address-redacted"),
            Fingerprints = port.Fingerprints.Select(static fingerprint => fingerprint with
            {
                Evidence = "[redacted]",
                Attributes = RemoteFingerprint.ReadOnlyAttributes(
                    fingerprint.Attributes
                        .Where(attribute => SafeFingerprintAttributes.Contains(attribute.Key))
                        .ToDictionary(static item => item.Key, static item => item.Value, StringComparer.Ordinal)),
            }).ToArray(),
            ProductCandidates = port.ProductCandidates.Select(static candidate => candidate with
            {
                Evidence = "[redacted]",
            }).ToArray(),
            Diagnostics = RedactDiagnostics(
                port.Diagnostics,
                "Remote endpoint details were redacted; use the diagnostic code for classification."),
        };

    private static IReadOnlyList<RemoteDiagnostic> RedactDiagnostics(
        IReadOnlyList<RemoteDiagnostic> diagnostics,
        string message) => diagnostics.Select(diagnostic => diagnostic with { Message = message }).ToArray();

    private static IReadOnlyList<RemoteAdvisoryDiagnostic> RedactAdvisoryDiagnostics(
        IReadOnlyList<RemoteAdvisoryDiagnostic> diagnostics,
        string message) => diagnostics.Select(diagnostic => diagnostic with { Message = message }).ToArray();

    private static string Alias(
        IReadOnlyDictionary<string, string> aliases,
        string value,
        string fallback) => aliases.TryGetValue(value, out var alias) ? alias : fallback;
}
