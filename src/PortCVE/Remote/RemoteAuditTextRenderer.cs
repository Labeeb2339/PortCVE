using System.Globalization;

namespace PortCVE.Remote;

internal static class RemoteAuditTextRenderer
{
    private const int MaximumRenderedAdvisoryMatches = 100;
    private const int MaximumEndpointSamplesPerResult = 5;
    private const int MaximumRenderedAssessmentDiagnostics = 50;
    private const int MaximumRenderedProviderDiagnostics = 50;

    internal static void Render(RemoteAuditReport report, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        output.WriteLine($"PortCVE remote assessment: {report.Selector}");
        output.WriteLine($"Profile: {report.ProbeProfile}; TCP ports: {FormatPorts(report.RequestedPorts)}");
        output.WriteLine();

        foreach (var host in report.Hosts)
        {
            output.WriteLine(host.ResolvedAddresses.Count == 0
                ? $"{host.Target}  unresolved"
                : $"{host.Target}  {string.Join(", ", host.ResolvedAddresses)}");

            foreach (var port in host.Ports.Where(static item => item.State == RemotePortState.Open))
            {
                var services = port.Fingerprints
                    .Select(static item => item.Service)
                    .Where(static item => !string.Equals(item, "unknown", StringComparison.Ordinal))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var products = port.ProductCandidates
                    .Select(static item => item.Version is null ? item.Product : $"{item.Product} {item.Version}")
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var identity = products.Length > 0
                    ? string.Join(", ", products)
                    : services.Length > 0
                        ? string.Join(", ", services)
                        : "service not identified";
                output.WriteLine($"  {port.Address}:{port.Port,-5} open  {identity}");
            }

            foreach (var diagnostic in host.Diagnostics)
            {
                error.WriteLine($"{diagnostic.Code}: {diagnostic.Message}");
            }

            foreach (var port in host.Ports.Where(static item =>
                item.State == RemotePortState.Open && item.Diagnostics.Count > 0))
            {
                foreach (var diagnostic in port.Diagnostics)
                {
                    error.WriteLine($"{host.Target}:{port.Port} {diagnostic.Code}: {diagnostic.Message}");
                }
            }
        }

        if (report.AdvisoryAssessments.Count > 0)
        {
            output.WriteLine();
            output.WriteLine("ADVISORY CORRELATION");
            var renderedAnyMatch = false;
            var renderedMatchCount = 0;
            var associationSummaries = BuildEndpointAssociationSummaries(report.AdvisoryAssessments);
            foreach (var result in report.AdvisoryResults)
            {
                if (renderedMatchCount >= MaximumRenderedAdvisoryMatches)
                {
                    break;
                }

                var matches = result.Matches
                    .Take(MaximumRenderedAdvisoryMatches - renderedMatchCount)
                    .ToArray();
                if (matches.Length == 0)
                {
                    continue;
                }

                _ = associationSummaries.TryGetValue(result.ResultId, out var associations);
                output.WriteLine(
                    $"  {result.ResultId}  {(associations?.Count ?? 0).ToString(CultureInfo.InvariantCulture)} endpoint association(s): "
                    + FormatEndpointSample(associations));
                foreach (var match in matches)
                {
                    renderedAnyMatch = true;
                    renderedMatchCount++;
                    output.WriteLine(
                        $"  {match.AdvisoryId,-18} {match.Severity.ToString().ToLowerInvariant(),-8} "
                        + $"{result.Product} {result.Version}  "
                        + $"[{match.Classification}; NVD {match.NvdStatus}]");
                    foreach (var limitation in match.Applicability.Limitations.Take(2))
                    {
                        output.WriteLine($"    - {limitation}");
                    }
                }
            }

            var totalMatchCount = report.AdvisoryResults.Sum(static result => result.Matches.Count);
            if (totalMatchCount > renderedMatchCount)
            {
                output.WriteLine(
                    $"  ... {(totalMatchCount - renderedMatchCount).ToString(CultureInfo.InvariantCulture)} "
                    + "additional shared advisory match(es) omitted from text; use JSON for the bounded full report.");
            }

            if (!renderedAnyMatch)
            {
                output.WriteLine("  No candidate advisory matches were returned for resolved strong identities.");
            }

            WriteBoundedAdvisoryDiagnostics(
                report.AdvisoryAssessments.SelectMany(static assessment => assessment.Diagnostics),
                MaximumRenderedAssessmentDiagnostics,
                "remote_assessment_diagnostics_truncated",
                "endpoint advisory diagnostic(s)",
                error);
            WriteBoundedAdvisoryDiagnostics(
                report.AdvisoryResults.SelectMany(static result => result.Diagnostics),
                MaximumRenderedProviderDiagnostics,
                "remote_provider_diagnostics_truncated",
                "provider diagnostic(s)",
                error);
        }

        foreach (var diagnostic in report.Diagnostics)
        {
            error.WriteLine($"{diagnostic.Code}: {diagnostic.Message}");
        }

        output.WriteLine();
        output.WriteLine(
            $"Summary: {report.Summary.OpenPortCount.ToString(CultureInfo.InvariantCulture)} open TCP endpoints; "
            + $"{report.Summary.AdvisoryMatchCount.ToString(CultureInfo.InvariantCulture)} unique candidate advisory matches "
            + $"({report.Summary.ConditionalCount.ToString(CultureInfo.InvariantCulture)} conditional, "
            + $"{report.Summary.InconclusiveCount.ToString(CultureInfo.InvariantCulture)} inconclusive); "
            + $"evidence {(report.Summary.IsComplete ? "complete" : "incomplete")}.");
        output.WriteLine(report.ClaimBoundary);
        if (report.NvdNotice is not null)
        {
            output.WriteLine(report.NvdNotice);
        }
    }

    private static string FormatPorts(IReadOnlyList<int> ports)
    {
        if (ports.Count <= 12)
        {
            return string.Join(",", ports);
        }

        return $"{ports.Count.ToString(CultureInfo.InvariantCulture)} selected";
    }

    private static void WriteBoundedAdvisoryDiagnostics(
        IEnumerable<Advisories.RemoteAdvisoryDiagnostic> diagnostics,
        int maximum,
        string truncationCode,
        string description,
        TextWriter error)
    {
        var count = 0;
        foreach (var diagnostic in diagnostics)
        {
            if (count < maximum)
            {
                error.WriteLine($"{diagnostic.Code}: {diagnostic.Message}");
            }

            count++;
        }

        if (count > maximum)
        {
            error.WriteLine(
                $"{truncationCode}: {(count - maximum).ToString(CultureInfo.InvariantCulture)} "
                + $"additional {description} omitted; use JSON for the bounded full report.");
        }
    }

    private static IReadOnlyDictionary<string, EndpointAssociationSummary> BuildEndpointAssociationSummaries(
        IReadOnlyList<RemoteAdvisoryAssessment> assessments)
    {
        var summaries = new Dictionary<string, EndpointAssociationSummary>(StringComparer.Ordinal);
        foreach (var assessment in assessments)
        {
            if (assessment.AdvisoryResultId is null)
            {
                continue;
            }

            if (!summaries.TryGetValue(assessment.AdvisoryResultId, out var summary))
            {
                summary = new();
                summaries.Add(assessment.AdvisoryResultId, summary);
            }

            summary.Count++;
            if (summary.Samples.Count < MaximumEndpointSamplesPerResult)
            {
                summary.Samples.Add(
                    $"{assessment.Target} [{assessment.Address}]:{assessment.Port.ToString(CultureInfo.InvariantCulture)}");
            }
        }

        return summaries;
    }

    private static string FormatEndpointSample(EndpointAssociationSummary? summary)
    {
        if (summary is null || summary.Count == 0)
        {
            return "none";
        }

        var remaining = summary.Count - summary.Samples.Count;
        return remaining == 0
            ? string.Join(", ", summary.Samples)
            : $"{string.Join(", ", summary.Samples)} (+{remaining.ToString(CultureInfo.InvariantCulture)} more)";
    }

    private sealed class EndpointAssociationSummary
    {
        internal int Count { get; set; }
        internal List<string> Samples { get; } = [];
    }
}
