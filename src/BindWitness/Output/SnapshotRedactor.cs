using System.Net;
using BindWitness.Collection;
using BindWitness.Domain;

namespace BindWitness.Output;

public static class SnapshotRedactor
{
    public static SystemSnapshot Redact(SystemSnapshot snapshot)
    {
        var interfaces = snapshot.Interfaces.Select(RedactInterface).ToArray();
        var listeners = snapshot.Listeners.Select(listener =>
        {
            var address = listener.BindScope switch
            {
                BindScope.Loopback => "loopback",
                BindScope.Wildcard => "any",
                BindScope.Interface => "interface",
                _ => "unknown",
            };
            return listener with
            {
                Key = SnapshotBuilder.CreateBindKey(listener.Protocol, listener.Family, address, listener.LocalPort),
                LocalAddress = address,
                BindSummary = RedactedBindSummary(listener.BindScope),
                Owner = listener.Owner with
                {
                    Pid = 0,
                    CreationTime = null,
                    ImagePath = null,
                    ImageSha256 = null,
                    ParentPid = null,
                    ParentImageName = null,
                    UserSid = null,
                    AccountName = null,
                    Limitations = RedactedLimitations(listener.Owner.Limitations),
                },
                ActiveOn = listener.ActiveOn.Select(RedactInterface).ToArray(),
                HostPolicy = listener.HostPolicy with
                {
                    Summary = RedactedPolicySummary(listener.HostPolicy.Verdict),
                    MatchingRules = listener.HostPolicy.MatchingRules.Select(static rule => rule with
                    {
                        Id = "redacted",
                        Name = "redacted rule",
                        Application = IsAny(rule.Application) ? rule.Application : "redacted",
                        Service = IsAny(rule.Service) ? rule.Service : "redacted",
                        LocalAddress = IsAny(rule.LocalAddress) ? rule.LocalAddress : "redacted",
                        RemoteAddress = IsAny(rule.RemoteAddress) ? rule.RemoteAddress : "redacted",
                        UnsupportedConstraints = rule.UnsupportedConstraints.Count == 0
                            ? []
                            : ["One or more rule constraints were redacted."],
                    }).ToArray(),
                    Limitations = RedactedLimitations(listener.HostPolicy.Limitations),
                },
                Evidence = [],
                Limitations = RedactedLimitations(listener.Limitations),
                ContainerExposures = listener.ContainerExposures?.Select(static container => container with
                {
                    ContainerId = "redacted",
                    ContainerName = "redacted container",
                    Image = "redacted image",
                    ImageId = null,
                    HostAddress = RedactContainerAddress(container.HostAddress),
                    Limitations = RedactedLimitations(container.Limitations),
                }).ToArray(),
            };
        }).ToArray();
        var reports = snapshot.Collectors.Select(report => report with
        {
            Diagnostics = report.Diagnostics.Select(RedactDiagnostic).ToArray(),
        }).ToArray();

        return snapshot with
        {
            Collectors = reports,
            Interfaces = interfaces,
            Listeners = listeners,
            Diagnostics = snapshot.Diagnostics.Select(RedactDiagnostic).ToArray(),
        };
    }

    public static IReadOnlyList<CollectorDiagnostic> RedactDiagnostics(
        IReadOnlyList<CollectorDiagnostic> diagnostics) =>
        diagnostics.Select(RedactDiagnostic).ToArray();

    public static IReadOnlyList<CollectorReport> RedactCollectorReports(
        IReadOnlyList<CollectorReport> reports) =>
        reports.Select(report => report with
        {
            Diagnostics = report.Diagnostics.Select(RedactDiagnostic).ToArray(),
        }).ToArray();

    private static NetworkInterfaceEvidence RedactInterface(NetworkInterfaceEvidence item) => item with
    {
        Id = "redacted",
        Name = $"interface-{item.Index}",
        Address = RedactAddress(item.Address),
    };

    private static string RedactAddress(string address)
    {
        if (!IPAddress.TryParse(address, out var parsed))
        {
            return "redacted";
        }

        if (IPAddress.IsLoopback(parsed))
        {
            return "loopback";
        }

        return parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? "redacted-ipv4"
            : "redacted-ipv6";
    }

    private static string RedactContainerAddress(string address) => address switch
    {
        "0.0.0.0" or "::" or "" => "any",
        _ => RedactAddress(address),
    };

    private static CollectorDiagnostic RedactDiagnostic(CollectorDiagnostic diagnostic) => diagnostic with
    {
        Message = "Diagnostic details redacted; rerun with --include-private to inspect them locally.",
    };

    private static IReadOnlyList<string> RedactedLimitations(IReadOnlyList<string> limitations) =>
        limitations.Count == 0 ? [] : ["Details redacted; rerun with --include-private to inspect them locally."];

    private static string RedactedBindSummary(BindScope scope) => scope switch
    {
        BindScope.Loopback => "host-local loopback binding",
        BindScope.Wildcard => "all-address wildcard binding",
        BindScope.Interface => "specific-interface binding",
        _ => "bind scope unknown",
    };

    private static string RedactedPolicySummary(FirewallVerdict verdict) => verdict switch
    {
        FirewallVerdict.Allow => "Static host policy indicates allow; identifying details were redacted.",
        FirewallVerdict.Block => "Static host policy indicates block; identifying details were redacted.",
        FirewallVerdict.Disabled => "Host firewall appears disabled on the assessed path.",
        FirewallVerdict.NotEvaluated => "Host policy was not evaluated for this binding.",
        _ => "Host-policy evidence is conditional, mixed, or incomplete.",
    };

    private static bool IsAny(string value) =>
        string.IsNullOrWhiteSpace(value)
        || value.Equals("Any", StringComparison.OrdinalIgnoreCase)
        || value.Equals("*", StringComparison.OrdinalIgnoreCase);
}
