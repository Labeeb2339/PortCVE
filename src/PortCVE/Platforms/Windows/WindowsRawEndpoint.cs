using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace PortCVE.Platforms.Windows;

public enum WindowsEndpointProtocol
{
    Tcp,
    Udp,
}

public sealed record WindowsRawEndpoint(
    WindowsEndpointProtocol Protocol,
    AddressFamily AddressFamily,
    IPAddress LocalAddress,
    int LocalPort,
    uint ProcessId,
    TcpState? TcpState);
