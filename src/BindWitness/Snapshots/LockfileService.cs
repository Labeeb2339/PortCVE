using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography;
using System.Text;
using BindWitness.Domain;

namespace BindWitness.Snapshots;

public sealed class LockfileService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower, allowIntegerValues: false) },
    };

    public ListenerLockfile Create(
        SystemSnapshot snapshot,
        bool includesUdp = false,
        bool includesHostPolicy = false,
        LockfileSelector? selector = null,
        bool includesContainerEvidence = false)
    {
        var listeners = snapshot.Listeners
            .Select(ToLockedListener)
            .OrderBy(static item => item.Key, StringComparer.Ordinal)
            .ToArray();

        var evidence = new LockfileEvidence(
            listeners.All(static item => item.OwnerIdentityStrength is OwnerIdentityStrength.Sha256 or OwnerIdentityStrength.ContainerImage or OwnerIdentityStrength.Service or OwnerIdentityStrength.Kernel)
                ? EvidenceCompleteness.Complete
                : EvidenceCompleteness.Partial,
            listeners.All(static item => item.Scope != BindScope.Unknown)
                ? EvidenceCompleteness.Complete
                : EvidenceCompleteness.Partial,
            !includesHostPolicy
                ? EvidenceCompleteness.NotCollected
                : snapshot.Listeners.All(static item =>
                    (item.HostPolicy.Verdict is FirewallVerdict.Allow or FirewallVerdict.Block or FirewallVerdict.Disabled
                        && item.HostPolicy.Confidence is Confidence.High or Confidence.Medium)
                    || (item.BindScope == BindScope.Loopback && item.HostPolicy.Verdict == FirewallVerdict.NotEvaluated))
                    ? EvidenceCompleteness.Complete
                    : EvidenceCompleteness.Partial,
            !includesContainerEvidence
                ? EvidenceCompleteness.NotCollected
                : snapshot.Collectors.Any(static report =>
                    report.Name == "docker" && report.Status == CollectorStatus.Complete)
                    ? EvidenceCompleteness.Complete
                    : EvidenceCompleteness.Partial);

        return new(
            ListenerLockfile.CurrentSchemaVersion,
            $"bindwitness/{snapshot.ToolVersion}",
            includesUdp,
            selector ?? new(null, null, null, null),
            evidence,
            listeners);
    }

    public async Task WriteAsync(
        string path,
        ListenerLockfile lockfile,
        bool overwrite,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        Validate(lockfile);
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tempPath = Path.Combine(
            directory ?? Directory.GetCurrentDirectory(),
            $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                tempPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, lockfile, JsonOptions, cancellationToken);
                await stream.WriteAsync("\r\n"u8.ToArray(), cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }

            File.Move(tempPath, fullPath, overwrite);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }

    public async Task<ListenerLockfile> ReadAsync(string path, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        await using var stream = File.OpenRead(Path.GetFullPath(path));
        var result = await JsonSerializer.DeserializeAsync<ListenerLockfile>(stream, JsonOptions, cancellationToken)
            ?? throw new InvalidDataException("The lockfile is empty or invalid.");

        if (result.SchemaVersion != ListenerLockfile.CurrentSchemaVersion)
        {
            throw new InvalidDataException(
                $"Unsupported lockfile schema {result.SchemaVersion}; expected {ListenerLockfile.CurrentSchemaVersion}.");
        }

        if (result.Evidence is null || result.Selector is null || result.Listeners is null)
        {
            throw new InvalidDataException("Lockfile is missing selector or evidence-completeness metadata.");
        }

        Validate(result);

        return result;
    }

    private static void Validate(ListenerLockfile lockfile)
    {
        if (string.IsNullOrWhiteSpace(lockfile.CreatedBy))
        {
            throw new InvalidDataException("Lockfile created_by must not be blank.");
        }

        if (!Enum.IsDefined(lockfile.Evidence.Ownership)
            || !Enum.IsDefined(lockfile.Evidence.BindScope)
            || !Enum.IsDefined(lockfile.Evidence.HostPolicy)
            || !Enum.IsDefined(lockfile.Evidence.Containers))
        {
            throw new InvalidDataException("Lockfile contains an unknown evidence-completeness value.");
        }

        if (lockfile.Selector.Process is not null || lockfile.Selector.Scope is not null)
        {
            throw new InvalidDataException("Lockfile schema v1 does not support process or scope selectors.");
        }

        if (lockfile.Selector.Port is < 1 or > 65535)
        {
            throw new InvalidDataException("Lockfile selector port must be from 1 to 65535.");
        }

        if (lockfile.Selector.Protocol is not null && !Enum.IsDefined(lockfile.Selector.Protocol.Value))
        {
            throw new InvalidDataException("Lockfile selector protocol is invalid.");
        }

        foreach (var listener in lockfile.Listeners)
        {
            if (listener is null)
            {
                throw new InvalidDataException("Lockfile listeners must not contain null entries.");
            }

            if (!Enum.IsDefined(listener.Protocol)
                || !Enum.IsDefined(listener.Family)
                || !Enum.IsDefined(listener.Scope)
                || !Enum.IsDefined(listener.OwnerIdentityStrength)
                || !Enum.IsDefined(listener.HostPolicyConfidence)
                || !Enum.IsDefined(listener.HostPolicy))
            {
                throw new InvalidDataException("Lockfile listener contains an unknown enum value.");
            }

            if (listener.Port is < 1 or > 65535)
            {
                throw new InvalidDataException($"Lockfile listener port {listener.Port} is invalid.");
            }

            var expectedAddress = listener.Scope switch
            {
                BindScope.Loopback => "loopback",
                BindScope.Wildcard => "any",
                BindScope.Interface => "interface",
                _ => "unknown",
            };
            var expectedKey = $"{listener.Protocol.ToString().ToLowerInvariant()}/"
                + $"{listener.Family.ToString().ToLowerInvariant()}/{expectedAddress}/{listener.Port}";
            if (!string.Equals(listener.Address, expectedAddress, StringComparison.Ordinal)
                || !string.Equals(listener.Key, expectedKey, StringComparison.Ordinal))
            {
                throw new InvalidDataException($"Lockfile listener key '{listener.Key}' is not canonical.");
            }

            if (string.IsNullOrWhiteSpace(listener.OwnerIdentity))
            {
                throw new InvalidDataException($"Lockfile listener '{listener.Key}' has no owner identity.");
            }

            if (!lockfile.IncludesUdp && listener.Protocol == TransportProtocol.Udp)
            {
                throw new InvalidDataException("Lockfile contains UDP entries but includes_udp is false.");
            }
        }
    }

    public static LockedListener ToLockedListener(ListenerEvidence listener)
    {
        var (ownerIdentity, strength) = OwnerIdentity(listener);
        var address = listener.BindScope switch
        {
            BindScope.Loopback => "loopback",
            BindScope.Wildcard => "any",
            BindScope.Interface => "interface",
            _ => "unknown",
        };
        var key = $"{listener.Protocol.ToString().ToLowerInvariant()}/"
            + $"{listener.Family.ToString().ToLowerInvariant()}/{address}/{listener.LocalPort}";

        return new(
            key,
            listener.Protocol,
            listener.Family,
            address,
            listener.LocalPort,
            listener.BindScope,
            ownerIdentity,
            strength,
            listener.HostPolicy.Confidence,
            listener.HostPolicy.Verdict);
    }

    private static (string Identity, OwnerIdentityStrength Strength) OwnerIdentity(ListenerEvidence listener)
    {
        var containers = listener.ContainerExposures ?? [];
        if (containers.Count > 0
            && containers.All(static item => !string.IsNullOrWhiteSpace(item.ImageId)))
        {
            var imageSet = string.Join(
                '\n',
                containers.Select(static item => item.ImageId!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Order(StringComparer.OrdinalIgnoreCase));
            var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(imageSet)))
                .ToLowerInvariant();
            return ($"container-image-set:{digest}", OwnerIdentityStrength.ContainerImage);
        }

        var owner = listener.Owner;
        if (!string.IsNullOrWhiteSpace(owner.ImageSha256))
        {
            return ($"sha256:{owner.ImageSha256}", OwnerIdentityStrength.Sha256);
        }

        if (owner.Services.Count == 1 && !owner.ServicesAreCandidates)
        {
            return ($"service:{owner.Services[0].ToLowerInvariant()}", OwnerIdentityStrength.Service);
        }

        if (owner.Pid is 0 or 4)
        {
            return ($"kernel:{owner.ImageName.ToLowerInvariant()}", OwnerIdentityStrength.Kernel);
        }

        if (!string.IsNullOrWhiteSpace(owner.ImageName) && !owner.ImageName.StartsWith("pid-", StringComparison.Ordinal))
        {
            return ($"process:{owner.ImageName.ToLowerInvariant()}", OwnerIdentityStrength.NameOnly);
        }

        return ("unknown", OwnerIdentityStrength.Unknown);
    }

    public static JsonSerializerOptions SerializerOptions => JsonOptions;
}
