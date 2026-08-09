using PortCVE.Domain;

namespace PortCVE.Collection;

internal sealed record DockerCorrelationResult(
    IReadOnlyList<ListenerEvidence> Listeners,
    IReadOnlyList<DockerPublishedPort> UnmatchedPublications);

internal static class DockerExposureCorrelator
{
    private const string CorrelationLimitation =
        "Docker Engine publication was correlated by protocol, host address, and host port; "
        + "the host socket may be owned by a Docker Desktop forwarding process.";

    internal static DockerCorrelationResult Correlate(
        IReadOnlyList<ListenerEvidence> listeners,
        IReadOnlyList<DockerPublishedPort> publishedPorts)
    {
        ArgumentNullException.ThrowIfNull(listeners);
        ArgumentNullException.ThrowIfNull(publishedPorts);

        var assignments = new Dictionary<int, List<ContainerExposureEvidence>>();
        var unmatched = new List<DockerPublishedPort>();
        foreach (var publication in publishedPorts)
        {
            var candidates = listeners
                .Select((listener, index) => (Index: index, Score: MatchSpecificity(listener, publication)))
                .Where(static candidate => candidate.Score >= 0)
                .ToArray();
            if (candidates.Length == 0)
            {
                unmatched.Add(publication);
                continue;
            }

            var bestScore = candidates.Max(static candidate => candidate.Score);
            var best = candidates.Where(candidate => candidate.Score == bestScore).ToArray();
            if (best.Length != 1)
            {
                unmatched.Add(publication);
                continue;
            }

            if (!assignments.TryGetValue(best[0].Index, out var exposures))
            {
                exposures = [];
                assignments.Add(best[0].Index, exposures);
            }

            exposures.Add(ToEvidence(publication));
        }

        var enriched = listeners.Select((listener, index) =>
        {
            if (!assignments.TryGetValue(index, out var assigned))
            {
                return listener;
            }

            var exposures = assigned
                .OrderBy(static item => item.ContainerName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(static item => item.Image, StringComparer.OrdinalIgnoreCase)
                .ThenBy(static item => item.ContainerPort)
                .ThenBy(static item => item.ContainerId, StringComparer.Ordinal)
                .ToArray();
            var evidence = listener.Evidence
                .Concat(exposures.Select(static exposure =>
                    $"Docker Engine maps {exposure.HostAddress}:{exposure.HostPort} to "
                    + $"{exposure.ContainerName}/{exposure.ContainerPort}/{exposure.Protocol.ToString().ToLowerInvariant()}."))
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            return listener with
            {
                ContainerExposures = exposures,
                Evidence = evidence,
            };
        }).ToArray();

        return new(enriched, unmatched);
    }

    private static int MatchSpecificity(ListenerEvidence listener, DockerPublishedPort publication)
    {
        if (listener.LocalPort != publication.HostPort
            || !publication.Protocol.Equals(
                listener.Protocol.ToString(),
                StringComparison.OrdinalIgnoreCase))
        {
            return -1;
        }

        if (!DockerPublishedPortParser.HostAddressMatches(publication.HostAddress, listener.LocalAddress))
        {
            return -1;
        }

        if (publication.HostAddress == "*")
        {
            return 0;
        }

        if (!System.Net.IPAddress.TryParse(publication.HostAddress, out var published)
            || !System.Net.IPAddress.TryParse(listener.LocalAddress, out var endpoint))
        {
            return 0;
        }

        if (published.Equals(endpoint))
        {
            return 3;
        }

        if (IsWildcard(endpoint))
        {
            return 2;
        }

        return IsWildcard(published) ? 1 : 0;
    }

    private static bool IsWildcard(System.Net.IPAddress address) =>
        address.Equals(System.Net.IPAddress.Any) || address.Equals(System.Net.IPAddress.IPv6Any);

    private static ContainerExposureEvidence ToEvidence(DockerPublishedPort publication)
    {
        var protocol = publication.Protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase)
            ? TransportProtocol.Tcp
            : TransportProtocol.Udp;
        return new(
            "docker",
            publication.ContainerId,
            string.IsNullOrWhiteSpace(publication.ContainerName)
                ? ShortId(publication.ContainerId)
                : publication.ContainerName,
            publication.Image,
            publication.ImageId,
            publication.HostAddress,
            publication.HostPort,
            publication.ContainerPort,
            protocol,
            Confidence.Medium,
            [CorrelationLimitation]);
    }

    private static string ShortId(string value) =>
        value.Length <= 12 ? value : value[..12];
}
