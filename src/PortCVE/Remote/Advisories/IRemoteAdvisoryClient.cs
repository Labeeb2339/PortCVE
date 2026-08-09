namespace PortCVE.Remote.Advisories;

internal interface IRemoteAdvisoryClient
{
    Task<RemoteAdvisoryResult> EnrichAsync(
        RemoteAdvisoryRequest request,
        CancellationToken cancellationToken);
}
