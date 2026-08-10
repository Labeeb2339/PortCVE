namespace PortCVE.Remote;

internal interface IRemoteHostScanner
{
    Task<RemoteHostReport> ScanAsync(
        RemoteScanOptions options,
        CancellationToken cancellationToken);
}
