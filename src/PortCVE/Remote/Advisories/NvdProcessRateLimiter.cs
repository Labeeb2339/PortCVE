namespace PortCVE.Remote.Advisories;

internal interface INvdRequestRateLimiter
{
    Task WaitAsync(CancellationToken cancellationToken);
    Task ApplyRetryAfterAsync(TimeSpan retryAfter, CancellationToken cancellationToken);
}

internal sealed class NvdProcessRateLimiter : INvdRequestRateLimiter
{
    internal static readonly TimeSpan ProductionMinimumSpacing = TimeSpan.FromSeconds(6);
    internal static readonly TimeSpan MaximumRetryAfter = TimeSpan.FromMinutes(5);

    internal static NvdProcessRateLimiter Shared { get; } = new(
        SystemRemoteAdvisoryClock.Instance,
        SystemRemoteAdvisoryDelay.Instance);

    private readonly IRemoteAdvisoryClock _clock;
    private readonly IRemoteAdvisoryDelay _delay;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private TimeSpan? _lastRequestAt;
    private TimeSpan _notBefore;

    internal NvdProcessRateLimiter(
        IRemoteAdvisoryClock clock,
        IRemoteAdvisoryDelay delay)
    {
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _delay = delay ?? throw new ArgumentNullException(nameof(delay));
    }

    public async Task WaitAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            TimeSpan delay;
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var now = _clock.MonotonicNow;
                var spacingDeadline = _lastRequestAt is null
                    ? TimeSpan.Zero
                    : _lastRequestAt.Value + ProductionMinimumSpacing;
                var deadline = spacingDeadline > _notBefore ? spacingDeadline : _notBefore;
                if (now >= deadline)
                {
                    _lastRequestAt = now;
                    return;
                }

                delay = deadline - now;
            }
            finally
            {
                _gate.Release();
            }

            // Do not hold the state gate while sleeping. A Retry-After response
            // from another request must be able to extend this deadline before
            // the pending request is released.
            await _delay.DelayAsync(delay, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task ApplyRetryAfterAsync(
        TimeSpan retryAfter,
        CancellationToken cancellationToken)
    {
        var bounded = retryAfter < ProductionMinimumSpacing
            ? ProductionMinimumSpacing
            : retryAfter > MaximumRetryAfter
                ? MaximumRetryAfter
                : retryAfter;

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var deadline = _clock.MonotonicNow + bounded;
            if (deadline > _notBefore)
            {
                _notBefore = deadline;
            }
        }
        finally
        {
            _gate.Release();
        }
    }
}
