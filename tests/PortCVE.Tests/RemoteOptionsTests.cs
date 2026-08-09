using System.Text;
using PortCVE.Remote;

namespace PortCVE.Tests;

public sealed class RemoteOptionsTests
{
    [Fact]
    public void Constructor_CopiesSortsAndDeduplicatesExplicitPorts()
    {
        var source = new[] { 443, 22, 443, 80 };

        var options = new RemoteScanOptions(
            "EXAMPLE.COM.",
            source,
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(2),
            concurrency: 4);

        source[0] = 1;
        Assert.Equal("example.com", options.Target);
        Assert.Equal([22, 80, 443], options.Ports);
        Assert.Equal(ProbeDepth.Passive, options.ProbeDepth);
        Assert.Equal(100, options.MaxConnectionsPerSecond);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65_536)]
    public void Constructor_RejectsPortsOutsideOneThrough65535(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RemoteScanOptions(
            "127.0.0.1",
            [port],
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(1),
            concurrency: 1));
    }

    [Theory]
    [InlineData("https://example.com")]
    [InlineData("example.com/path")]
    [InlineData("host name")]
    [InlineData("example.com\r\nInjected: true")]
    public void Constructor_RejectsAnythingOtherThanOneHostOrIp(string target)
    {
        Assert.Throws<ArgumentException>(() => new RemoteScanOptions(
            target,
            [443],
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(1),
            concurrency: 1));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(10_001)]
    public void Constructor_RejectsInvalidConnectionRate(int rate)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RemoteScanOptions(
            "127.0.0.1",
            [443],
            TimeSpan.FromSeconds(1),
            TimeSpan.FromSeconds(1),
            concurrency: 1,
            maxConnectionsPerSecond: rate));
    }

    [Fact]
    public void EvidenceSanitizer_RemovesControlsAndHonorsUtf8ByteLimit()
    {
        var sanitized = RemoteEvidenceSanitizer.Sanitize(
            "hello\0\r\nworld\u2028ééé",
            maximumUtf8Bytes: 15);

        Assert.DoesNotContain(sanitized, static character => char.IsControl(character));
        Assert.DoesNotContain('\u2028', sanitized);
        Assert.InRange(Encoding.UTF8.GetByteCount(sanitized), 1, 15);
        Assert.StartsWith("hello", sanitized, StringComparison.Ordinal);
        Assert.Contains('\uFFFD', sanitized);
    }

    [Fact]
    public async Task MonotonicRateLimiter_IsCancellationSafeWhileWaitingForNextPermit()
    {
        var limiter = new MonotonicConnectionRateLimiter(1);
        await limiter.WaitAsync(CancellationToken.None);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await limiter.WaitAsync(cancellation.Token));
    }
}
