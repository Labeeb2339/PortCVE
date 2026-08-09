using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using BindWitness.Platforms.Windows;

namespace BindWitness.Tests;

public sealed class WindowsEndpointCollectorTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(53)]
    [InlineData(443)]
    [InlineData(49152)]
    [InlineData(65535)]
    public void DecodePort_ConvertsNetworkByteOrder(int port)
    {
        var networkOrderPort = unchecked(
            (ushort)IPAddress.HostToNetworkOrder(unchecked((short)port)));

        Assert.Equal(port, WindowsEndpointCollector.DecodePort(networkOrderPort));
    }

    [Theory]
    [InlineData(0x16000000u, 22L)]
    [InlineData(22u, 22L)]
    [InlineData(0x02000000u, 2L)]
    [InlineData(2u, 2L)]
    public void DecodeScopeId_AcceptsDocumentedAndObservedWindowsOrdering(uint raw, long expected)
    {
        Assert.Equal(expected, WindowsEndpointCollector.DecodeScopeId(raw));
    }

    [Fact]
    public void Collect_FindsLiveTcpLoopbackListenerOwnedByCurrentProcess()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var localEndpoint = Assert.IsType<IPEndPoint>(listener.LocalEndpoint);
        var collector = new WindowsEndpointCollector();
        WindowsRawEndpoint? match = null;
        var timeout = Stopwatch.StartNew();

        do
        {
            match = collector.Collect().FirstOrDefault(endpoint =>
                endpoint.Protocol == WindowsEndpointProtocol.Tcp &&
                endpoint.AddressFamily == AddressFamily.InterNetwork &&
                endpoint.LocalAddress.Equals(IPAddress.Loopback) &&
                endpoint.LocalPort == localEndpoint.Port &&
                endpoint.ProcessId == (uint)Environment.ProcessId &&
                endpoint.TcpState == TcpState.Listen);

            if (match is null)
            {
                Thread.Sleep(25);
            }
        }
        while (match is null && timeout.Elapsed < TimeSpan.FromSeconds(2));

        Assert.NotNull(match);
    }
}
