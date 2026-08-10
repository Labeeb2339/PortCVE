using System.Diagnostics;

namespace PortCVE.Remote.Advisories;

internal interface IRemoteAdvisoryClock
{
    DateTimeOffset UtcNow { get; }
    TimeSpan MonotonicNow { get; }
}

internal interface IRemoteAdvisoryDelay
{
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

internal sealed class SystemRemoteAdvisoryClock : IRemoteAdvisoryClock
{
    internal static SystemRemoteAdvisoryClock Instance { get; } = new();

    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

    public TimeSpan MonotonicNow => Stopwatch.GetElapsedTime(0, Stopwatch.GetTimestamp());
}

internal sealed class SystemRemoteAdvisoryDelay : IRemoteAdvisoryDelay
{
    internal static SystemRemoteAdvisoryDelay Instance { get; } = new();

    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        Task.Delay(delay, cancellationToken);
}
