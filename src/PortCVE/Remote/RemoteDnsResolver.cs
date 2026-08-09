using System.Net;
using System.Net.Sockets;

namespace PortCVE.Remote;

internal interface IRemoteDnsResolver
{
    Task<IPAddress[]> ResolveAsync(string target, CancellationToken cancellationToken);
}

internal sealed class SystemRemoteDnsResolver : IRemoteDnsResolver
{
    public Task<IPAddress[]> ResolveAsync(string target, CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(target, out var address))
        {
            return Task.FromResult<IPAddress[]>([address]);
        }

        return Dns.GetHostAddressesAsync(target, AddressFamily.Unspecified, cancellationToken);
    }
}
