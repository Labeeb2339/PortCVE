namespace PortCVE.Collection;

public sealed record DockerPublishedPort(
    string ContainerId,
    string ContainerName,
    string Image,
    string ImageId,
    string HostAddress,
    int HostPort,
    int ContainerPort,
    string Protocol);
