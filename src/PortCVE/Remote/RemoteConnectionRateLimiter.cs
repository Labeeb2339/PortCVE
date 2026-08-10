using System.Diagnostics;

namespace PortCVE.Remote;

internal interface IRemoteConnectionRateLimiter
{
    ValueTask WaitAsync(CancellationToken cancellationToken);
}

internal sealed class MonotonicConnectionRateLimiter : IRemoteConnectionRateLimiter
{
    private readonly object sync = new();
    private readonly long intervalTicks;
    private long nextPermitTimestamp;

    public MonotonicConnectionRateLimiter(int maximumConnectionsPerSecond)
    {
        if (maximumConnectionsPerSecond is < 1 or > RemoteScanOptions.MaximumConnectionsPerSecondLimit)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumConnectionsPerSecond));
        }

        intervalTicks = Math.Max(
            1,
            (long)Math.Ceiling((double)Stopwatch.Frequency / maximumConnectionsPerSecond));
    }

    public async ValueTask WaitAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        long permitTimestamp;
        lock (sync)
        {
            var now = Stopwatch.GetTimestamp();
            permitTimestamp = Math.Max(now, nextPermitTimestamp);
            nextPermitTimestamp = permitTimestamp > long.MaxValue - intervalTicks
                ? long.MaxValue
                : permitTimestamp + intervalTicks;
        }

        while (true)
        {
            var remainingTicks = permitTimestamp - Stopwatch.GetTimestamp();
            if (remainingTicks <= 0)
            {
                return;
            }

            var delay = TimeSpan.FromSeconds((double)remainingTicks / Stopwatch.Frequency);
            await Task.Delay(delay, cancellationToken);
        }
    }
}
