using BindWitness.Analysis;
using BindWitness.Domain;

namespace BindWitness.Output;

public static class TextRenderer
{
    public static void RenderList(IReadOnlyList<ListenerEvidence> listeners, TextWriter output)
    {
        if (listeners.Count == 0)
        {
            output.WriteLine("No matching local endpoints.");
            return;
        }

        var rows = listeners.Select(listener => new[]
        {
            ProtocolLabel(listener),
            FormatEndpoint(listener.LocalAddress, listener.LocalPort),
            listener.SocketState,
            listener.BindScope.ToString().ToLowerInvariant(),
            listener.Owner.ImageName,
            ContainerLabel(listener),
            listener.Owner.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture),
            PolicyLabel(listener.HostPolicy.Verdict),
        }).ToArray();
        var headers = new[] { "PROTO", "LOCAL", "STATE", "SCOPE", "OWNER", "CONTAINER", "PID", "HOST POLICY" };
        var widths = Enumerable.Range(0, headers.Length)
            .Select(index => Math.Min(42, rows.Select(row => row[index].Length).Append(headers[index].Length).Max()))
            .ToArray();

        WriteRow(headers, widths, output);
        WriteRow(widths.Select(static width => new string('-', width)).ToArray(), widths, output);
        foreach (var row in rows)
        {
            WriteRow(row, widths, output);
        }
    }

    public static void RenderDetails(
        IReadOnlyList<ListenerEvidence> listeners,
        bool showEvidence,
        TextWriter output)
    {
        for (var index = 0; index < listeners.Count; index++)
        {
            if (index > 0)
            {
                output.WriteLine();
                output.WriteLine(new string('-', 72));
                output.WriteLine();
            }

            var listener = listeners[index];
            output.WriteLine($"{ProtocolLabel(listener)}  {FormatEndpoint(listener.LocalAddress, listener.LocalPort)}  {listener.SocketState}");
            output.WriteLine();
            output.WriteLine("OWNER");
            WriteField(output, "Process", $"{listener.Owner.ImageName}  pid {listener.Owner.Pid}");
            WriteField(output, "Binary", listener.Owner.ImagePath ?? "unavailable");
            if (listener.Owner.ParentPid is not null)
            {
                WriteField(output, "Parent", $"{listener.Owner.ParentImageName ?? "unknown"}  pid {listener.Owner.ParentPid}");
            }

            WriteField(output, "User", listener.Owner.AccountName ?? listener.Owner.UserSid ?? "unavailable");
            if (listener.Owner.Services.Count > 0)
            {
                WriteField(
                    output,
                    listener.Owner.ServicesAreCandidates ? "Svc candidates" : "Service",
                    string.Join(", ", listener.Owner.Services));
            }

            var containers = listener.ContainerExposures ?? [];
            if (containers.Count > 0)
            {
                output.WriteLine();
                output.WriteLine("CONTAINER PUBLICATION");
                foreach (var container in containers)
                {
                    var identity = string.IsNullOrWhiteSpace(container.ContainerName)
                        ? ShortId(container.ContainerId)
                        : container.ContainerName;
                    WriteField(output, "Container", $"{identity}  ({container.Runtime})");
                    WriteField(output, "Image", container.Image);
                    WriteField(
                        output,
                        "Mapping",
                        $"{FormatEndpoint(container.HostAddress, container.HostPort)} -> "
                        + $"{container.ContainerPort}/{container.Protocol.ToString().ToLowerInvariant()}");
                    WriteField(output, "Confidence", container.Confidence.ToString().ToLowerInvariant());
                }
            }

            output.WriteLine();
            output.WriteLine("BIND");
            WriteField(output, "Scope", listener.BindSummary);
            if (listener.ActiveOn.Count == 0)
            {
                WriteField(output, "Active on", listener.BindScope == BindScope.Loopback ? "loopback" : "not mapped");
            }
            else
            {
                var first = true;
                foreach (var item in listener.ActiveOn)
                {
                    WriteField(output, first ? "Active on" : string.Empty,
                        $"{item.Name}  {item.Address}/{item.PrefixLength}  ({item.Profile})");
                    first = false;
                }
            }

            output.WriteLine();
            output.WriteLine("HOST POLICY");
            WriteField(output, PolicyLabel(listener.HostPolicy.Verdict), listener.HostPolicy.Summary);
            WriteField(output, "Confidence", listener.HostPolicy.Confidence.ToString().ToLowerInvariant());

            output.WriteLine();
            output.WriteLine("REACHABILITY");
            WriteField(output, "Local socket", listener.Protocol == TransportProtocol.Tcp
                ? "LISTENING - application acceptance was not tested"
                : "BOUND - receive behavior was not proven");
            WriteField(output, "LAN/routed", ReachabilityLabel(listener));
            WriteField(output, "Internet", "UNKNOWN - router, NAT, cloud controls, and the remote path were not tested");

            if (showEvidence)
            {
                output.WriteLine();
                output.WriteLine("EVIDENCE");
                foreach (var item in listener.Evidence)
                {
                    output.WriteLine($"  - {item}");
                }

                foreach (var rule in listener.HostPolicy.MatchingRules)
                {
                    output.WriteLine($"  - Firewall rule {rule.Name} ({rule.Action}, {rule.Protocol}/{rule.LocalPort})");
                }
            }

            var limitations = listener.Limitations
                .Concat(listener.HostPolicy.Limitations)
                .Concat((listener.ContainerExposures ?? []).SelectMany(static item => item.Limitations))
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (limitations.Length > 0)
            {
                output.WriteLine();
                output.WriteLine("LIMITATIONS");
                foreach (var item in limitations)
                {
                    output.WriteLine($"  - {item}");
                }
            }
        }
    }

    public static void RenderChanges(IReadOnlyList<ListenerChange> changes, TextWriter output)
    {
        if (changes.Count == 0)
        {
            output.WriteLine("No listener drift detected.");
            return;
        }

        foreach (var change in changes)
        {
            var marker = change.Kind switch
            {
                ListenerChangeKind.Added or ListenerChangeKind.ExposureExpanded => "+",
                ListenerChangeKind.Removed or ListenerChangeKind.ExposureNarrowed => "-",
                _ => "~",
            };
            output.WriteLine($"{marker} {change.Key}  {change.Kind.ToString().ToLowerInvariant()}");
            output.WriteLine($"  {change.Summary}");
        }
    }

    public static void RenderDiagnostics(
        IReadOnlyList<CollectorDiagnostic> diagnostics,
        TextWriter error)
    {
        foreach (var diagnostic in diagnostics)
        {
            error.WriteLine($"warning: {diagnostic.Collector}/{diagnostic.Code}: {diagnostic.Message}");
        }
    }

    private static string ReachabilityLabel(ListenerEvidence listener) => listener.BindScope switch
    {
        BindScope.Loopback => "HOST-LOCAL BIND - application behavior not tested",
        _ when listener.HostPolicy.Verdict == FirewallVerdict.Allow => "STATIC HOST POLICY INDICATES ALLOW - packet path not tested",
        _ when listener.HostPolicy.Verdict == FirewallVerdict.Block => "STATIC HOST POLICY INDICATES BLOCK - packet path not tested",
        _ when listener.HostPolicy.Verdict == FirewallVerdict.Disabled => "HOST FIREWALL DISABLED - remote path not verified",
        _ => "UNKNOWN - host-policy evidence is incomplete or conditional",
    };

    private static string PolicyLabel(FirewallVerdict verdict) => verdict switch
    {
        FirewallVerdict.Allow => "STATIC ALLOW",
        FirewallVerdict.Block => "STATIC BLOCK",
        FirewallVerdict.NotEvaluated => "NOT CHECKED",
        _ => verdict.ToString().ToUpperInvariant(),
    };

    private static string ProtocolLabel(ListenerEvidence listener) =>
        $"{listener.Protocol.ToString().ToUpperInvariant()}{(listener.Family == IpFamily.Ipv4 ? '4' : '6')}";

    private static string ContainerLabel(ListenerEvidence listener)
    {
        var containers = listener.ContainerExposures ?? [];
        if (containers.Count == 0)
        {
            return "-";
        }

        var first = string.IsNullOrWhiteSpace(containers[0].ContainerName)
            ? ShortId(containers[0].ContainerId)
            : containers[0].ContainerName;
        return containers.Count == 1 ? first : $"{first} +{containers.Count - 1}";
    }

    private static string ShortId(string value) =>
        value.Length <= 12 ? value : value[..12];

    private static string FormatEndpoint(string address, int port) =>
        address.Contains(':', StringComparison.Ordinal) ? $"[{address}]:{port}" : $"{address}:{port}";

    private static void WriteField(TextWriter output, string label, string value) =>
        output.WriteLine($"  {label,-12} {value}");

    private static void WriteRow(string[] values, int[] widths, TextWriter output)
    {
        for (var index = 0; index < values.Length; index++)
        {
            var value = values[index].Length > widths[index]
                ? values[index][..Math.Max(1, widths[index] - 1)] + "…"
                : values[index];
            output.Write(value.PadRight(widths[index]));
            if (index < values.Length - 1)
            {
                output.Write("  ");
            }
        }

        output.WriteLine();
    }
}
