namespace PortCVE.Verification;

internal static class ExposureVerificationTextRenderer
{
    internal static void Render(
        ExposureVerificationReport report,
        TextWriter output,
        TextWriter error)
    {
        output.WriteLine($"PortCVE exposure verification: {report.Association.ImportedTarget}");
        output.WriteLine($"Vantage          {report.Association.Vantage} (operator supplied)");
        output.WriteLine($"Evidence complete {(report.Summary.IsComplete ? "yes" : "no")}");
        output.WriteLine(
            $"Endpoints {report.Summary.OutsideEndpointCount}  "
            + $"open {report.Summary.OutsideOpenCount}  "
            + $"correlated {report.Summary.CorrelatedOpenCount}  "
            + $"outside-only {report.Summary.OutsideOnlyCount}  "
            + $"inconclusive {report.Summary.InconclusiveCount}");
        output.WriteLine(
            $"Findings {report.Summary.FindingGroupCount}  "
            + $"critical {report.Summary.CriticalCount}  high {report.Summary.HighCount}");

        if (report.Endpoints.Count == 0)
        {
            output.WriteLine("No useful endpoint observations were retained for the selected target.");
        }

        foreach (var endpoint in report.Endpoints)
        {
            output.WriteLine();
            output.WriteLine(
                $"{endpoint.Protocol}/{endpoint.ExternalPort} -> local {endpoint.Protocol}/{endpoint.LocalPort}  "
                + endpoint.Correlation.ToString().ToLowerInvariant());
            var states = endpoint.OutsideObservations.Select(static item => item.State)
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal);
            output.WriteLine($"  Outside  {string.Join(", ", states)}");
            if (endpoint.LocalListeners.Count == 0)
            {
                output.WriteLine("  Local    no matching live listener observed");
            }
            else
            {
                foreach (var listener in endpoint.LocalListeners)
                {
                    output.WriteLine(
                        $"  Local    {listener.BindScope.ToString().ToLowerInvariant()} "
                        + $"{listener.ImageName} [{listener.OwnerIdentityStrength.ToString().ToLowerInvariant()}] "
                        + $"firewall={listener.HostPolicy.ToString().ToLowerInvariant()}/"
                        + listener.HostPolicyConfidence.ToString().ToLowerInvariant());
                }
            }

            foreach (var finding in endpoint.Findings)
            {
                var advisory = finding.AdvisoryIds.Count == 0
                    ? finding.FindingGroupId
                    : string.Join(",", finding.AdvisoryIds);
                output.WriteLine(
                    $"  Finding  {finding.HighestReportedSeverity.ToUpperInvariant(),-8} {advisory} "
                    + $"[{finding.Correlation.ToString().ToLowerInvariant()}] {finding.Title}");
            }
        }

        if (report.TargetFindings.Count > 0)
        {
            output.WriteLine();
            output.WriteLine("Target-level findings without a unique endpoint:");
            foreach (var finding in report.TargetFindings)
            {
                output.WriteLine(
                    $"  {finding.HighestReportedSeverity.ToUpperInvariant(),-8} "
                    + $"{finding.FindingGroupId} {finding.Title}");
            }
        }

        output.WriteLine();
        output.WriteLine("Boundary: correlation supports attribution; it does not prove reachability, applicability, or exploitability.");
        foreach (var diagnostic in report.Diagnostics)
        {
            error.WriteLine($"{diagnostic.Code}: {diagnostic.Message}");
        }
    }
}
