using System.Text.Json;
using System.Text.RegularExpressions;

namespace PortCVE.Vulnerabilities;

internal enum TrivyDatabaseOperation
{
    Status,
    Update,
}

internal enum TrivyDatabaseState
{
    Ready,
    Missing,
    Stale,
    Invalid,
    Unavailable,
    Failed,
}

internal sealed record TrivyDatabaseStatus(
    int SchemaVersion,
    string Provider,
    TrivyDatabaseOperation Operation,
    TrivyDatabaseState State,
    bool Ready,
    bool NetworkRequested,
    string? ExecutablePath,
    string? EngineVersion,
    string? CacheDirectory,
    int? DatabaseSchemaVersion,
    DateTimeOffset? DatabaseUpdatedAt,
    DateTimeOffset? DatabaseNextUpdate,
    long? DatabaseAgeSeconds,
    long MaximumDatabaseAgeSeconds,
    long DurationMs,
    string Code,
    string Message);

internal interface ITrivyDatabaseService
{
    Task<TrivyDatabaseStatus> GetStatusAsync(CancellationToken cancellationToken);

    Task<TrivyDatabaseStatus> UpdateAsync(CancellationToken cancellationToken);
}

internal sealed partial class TrivyDatabaseService : ITrivyDatabaseService
{
    internal const int StatusSchemaVersion = TrivyDatabaseDocument.CurrentSchemaVersion;
    internal static readonly TimeSpan MaximumDatabaseAge = TimeSpan.FromHours(72);

    private const int MaximumMetadataBytes = 1024 * 1024;
    private const int MaximumVersionOutputCharacters = 64 * 1024;
    private const int MaximumUpdateOutputCharacters = 256 * 1024;
    private static readonly TimeSpan VersionTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan DatabaseValidationTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DefaultUpdateTimeout = TimeSpan.FromMinutes(10);
    private static readonly string[] RemovedEnvironmentVariables =
    [
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "CI_JOB_TOKEN",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ];
    private static readonly string[] RemovedEnvironmentVariablePrefixes =
    [
        "TRIVY_",
        "DOCKER_",
        "CONTAINERD_",
        "PODMAN_",
        "AWS_",
        "AZURE_",
        "GOOGLE_",
        "OCI_",
        "ORAS_",
    ];

    private readonly string? configuredExecutable;
    private readonly string configuredCacheDirectory;
    private readonly IProcessRunner processRunner;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan updateTimeout;
    private readonly string tempRootDirectory;
    private readonly Func<string?, LocalPathValidation> executableLocator;
    private readonly Func<string, LocalPathValidation> cachePathValidator;

    public TrivyDatabaseService()
        : this(
            Environment.GetEnvironmentVariable("PORTCVE_TRIVY_PATH"),
            ResolveCacheDirectory(),
            new BoundedProcessRunner(),
            TimeProvider.System,
            DefaultUpdateTimeout,
            ResolveTempRootDirectory())
    {
    }

    internal TrivyDatabaseService(
        string? configuredExecutable,
        string cacheDirectory,
        IProcessRunner processRunner,
        TimeProvider timeProvider,
        TimeSpan updateTimeout,
        string? tempRootDirectory = null,
        Func<string?, LocalPathValidation>? executableLocator = null,
        Func<string, LocalPathValidation>? cachePathValidator = null)
    {
        if (updateTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(updateTimeout));
        }

        this.configuredExecutable = configuredExecutable;
        configuredCacheDirectory = cacheDirectory;
        this.processRunner = processRunner;
        this.timeProvider = timeProvider;
        this.updateTimeout = updateTimeout;
        this.tempRootDirectory = tempRootDirectory ?? ResolveTempRootDirectory();
        this.executableLocator = executableLocator ?? LocateExecutable;
        this.cachePathValidator = cachePathValidator ?? LocalPathPolicy.ValidateLocalDirectoryPath;
    }

    public Task<TrivyDatabaseStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        RunAsync(TrivyDatabaseOperation.Status, cancellationToken);

    public Task<TrivyDatabaseStatus> UpdateAsync(CancellationToken cancellationToken) =>
        RunAsync(TrivyDatabaseOperation.Update, cancellationToken);

    internal static LocalPathValidation LocateExecutable(string? configuredPath)
    {
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            try
            {
                if (!Path.IsPathFullyQualified(configuredPath))
                {
                    return new(
                        false,
                        null,
                        "trivy_executable_invalid",
                        "PORTCVE_TRIVY_PATH must be an absolute path to a local executable.");
                }

                if (!Path.GetExtension(configuredPath).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    return new(
                        false,
                        null,
                        "trivy_executable_invalid",
                        "PORTCVE_TRIVY_PATH must name a Windows .exe file.");
                }

                return LocalPathPolicy.ValidateExistingTrivyExecutable(configuredPath);
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
            {
                return new(
                    false,
                    null,
                    "trivy_executable_invalid",
                    "PORTCVE_TRIVY_PATH is not a valid local executable path.");
            }
        }

        var pathValue = Environment.GetEnvironmentVariable("PATH");
        foreach (var entry in (pathValue ?? string.Empty).Split(
            Path.PathSeparator,
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var directory = Environment.ExpandEnvironmentVariables(entry.Trim('"'));
            if (!Path.IsPathFullyQualified(directory))
            {
                continue;
            }

            var directoryValidation = LocalPathPolicy.ValidateLocalDirectoryPath(directory);
            if (!directoryValidation.IsValid)
            {
                continue;
            }

            string candidate;
            try
            {
                candidate = Path.Combine(directoryValidation.FullPath!, "trivy.exe");
            }
            catch (ArgumentException)
            {
                continue;
            }

            if (!File.Exists(candidate))
            {
                continue;
            }

            return LocalPathPolicy.ValidateExistingTrivyExecutable(candidate);
        }

        return new(
            false,
            null,
            "trivy_executable_not_found",
            "Trivy was not found on the local PATH. Set PORTCVE_TRIVY_PATH to its absolute path.");
    }

    private async Task<TrivyDatabaseStatus> RunAsync(
        TrivyDatabaseOperation operation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var networkRequested = operation == TrivyDatabaseOperation.Update;
        var executableValidation = executableLocator(configuredExecutable);
        if (!executableValidation.IsValid)
        {
            return Status(
                operation,
                TrivyDatabaseState.Unavailable,
                networkRequested,
                null,
                null,
                SafeFullPath(configuredCacheDirectory),
                null,
                0,
                executableValidation.Code,
                "Trivy could not be resolved to a safe existing local executable.");
        }

        var executablePath = executableValidation.FullPath!;
        var cacheValidation = cachePathValidator(configuredCacheDirectory);
        if (!cacheValidation.IsValid)
        {
            return Status(
                operation,
                TrivyDatabaseState.Invalid,
                networkRequested,
                executablePath,
                null,
                null,
                null,
                0,
                "trivy_cache_unsafe",
                "The configured Trivy cache directory is not a safe local directory.");
        }

        var cacheDirectory = cacheValidation.FullPath!;
        if (networkRequested)
        {
            try
            {
                Directory.CreateDirectory(cacheDirectory);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return Status(
                    operation,
                    TrivyDatabaseState.Failed,
                    true,
                    executablePath,
                    null,
                    cacheDirectory,
                    null,
                    0,
                    "trivy_cache_create_failed",
                    "PortCVE could not create the local Trivy cache directory.");
            }

            cacheValidation = cachePathValidator(cacheDirectory);
            if (!cacheValidation.IsValid)
            {
                return Status(
                    operation,
                    TrivyDatabaseState.Invalid,
                    true,
                    executablePath,
                    null,
                    null,
                    null,
                    0,
                    "trivy_cache_unsafe",
                    "The Trivy cache directory became unsafe before the update started.");
            }
        }

        var temp = CreateInvocationTempDirectory();
        if (temp.Path is null)
        {
            return Status(
                operation,
                TrivyDatabaseState.Failed,
                networkRequested,
                executablePath,
                null,
                cacheDirectory,
                null,
                0,
                "trivy_temp_unavailable",
                "PortCVE could not create a safe local Trivy temporary directory.");
        }

        try
        {
            executableValidation = LocalPathPolicy.ValidateExistingTrivyExecutable(executablePath);
            if (!executableValidation.IsValid)
            {
                return Status(
                    operation,
                    TrivyDatabaseState.Unavailable,
                    networkRequested,
                    null,
                    null,
                    cacheDirectory,
                    null,
                    0,
                    "trivy_executable_changed",
                    "The validated Trivy executable became unavailable or unsafe before launch.");
            }

            var versionResult = await processRunner.RunAsync(
                CreateVersionInvocation(executablePath, cacheDirectory, temp.Path),
                cancellationToken);
            var versionFailure = VersionFailure(
                operation,
                networkRequested,
                executablePath,
                cacheDirectory,
                versionResult);
            if (versionFailure is not null)
            {
                return versionFailure;
            }

            var engineVersion = ParseEngineVersion(versionResult.StandardOutput);
            if (engineVersion is null)
            {
                return Status(
                    operation,
                    TrivyDatabaseState.Unavailable,
                    networkRequested,
                    executablePath,
                    null,
                    cacheDirectory,
                    null,
                    versionResult.DurationMs,
                    "trivy_version_invalid",
                    "Trivy returned an unrecognized version response.");
            }

            var durationMs = versionResult.DurationMs;
            if (networkRequested)
            {
                cacheValidation = cachePathValidator(cacheDirectory);
                executableValidation = LocalPathPolicy.ValidateExistingTrivyExecutable(executablePath);
                if (!cacheValidation.IsValid || !executableValidation.IsValid)
                {
                    return Status(
                        operation,
                        TrivyDatabaseState.Invalid,
                        true,
                        executableValidation.IsValid ? executablePath : null,
                        engineVersion,
                        cacheValidation.IsValid ? cacheDirectory : null,
                        null,
                        durationMs,
                        "trivy_update_path_changed",
                        "A validated Trivy path became unavailable or unsafe before the update started.");
                }

                var updateResult = await processRunner.RunAsync(
                    CreateUpdateInvocation(executablePath, cacheDirectory, temp.Path),
                    cancellationToken);
                durationMs += updateResult.DurationMs;
                var updateFailure = UpdateFailure(
                    operation,
                    executablePath,
                    engineVersion,
                    cacheDirectory,
                    durationMs,
                    updateResult);
                if (updateFailure is not null)
                {
                    return updateFailure;
                }
            }

            cacheValidation = cachePathValidator(cacheDirectory);
            if (!cacheValidation.IsValid)
            {
                return Status(
                    operation,
                    TrivyDatabaseState.Invalid,
                    networkRequested,
                    executablePath,
                    engineVersion,
                    null,
                    null,
                    durationMs,
                    "trivy_cache_changed",
                    "The Trivy cache directory became unavailable or unsafe before verification.");
            }

            var databaseStatus = InspectDatabase(
                operation,
                networkRequested,
                executablePath,
                engineVersion,
                cacheDirectory,
                durationMs);
            if (!databaseStatus.Ready)
            {
                return databaseStatus;
            }

            var validationTarget = CreateDatabaseValidationTarget(temp.Path);
            if (validationTarget is null)
            {
                return databaseStatus with
                {
                    State = TrivyDatabaseState.Failed,
                    Ready = false,
                    Code = "trivy_database_validation_target_failed",
                    Message = "PortCVE could not create an empty local database-validation target.",
                };
            }

            cacheValidation = cachePathValidator(cacheDirectory);
            executableValidation = LocalPathPolicy.ValidateExistingTrivyExecutable(executablePath);
            if (!cacheValidation.IsValid || !executableValidation.IsValid)
            {
                return databaseStatus with
                {
                    State = TrivyDatabaseState.Invalid,
                    Ready = false,
                    ExecutablePath = executableValidation.IsValid ? executablePath : null,
                    CacheDirectory = cacheValidation.IsValid ? cacheDirectory : null,
                    Code = "trivy_database_validation_path_changed",
                    Message = "A validated Trivy path became unavailable or unsafe before database validation.",
                };
            }

            var validationResult = await processRunner.RunAsync(
                CreateDatabaseValidationInvocation(
                    executablePath,
                    cacheDirectory,
                    temp.Path,
                    validationTarget),
                cancellationToken);
            return ApplyDatabaseValidationResult(databaseStatus, validationResult);
        }
        finally
        {
            TryDeleteInvocationTempDirectory(tempRootDirectory, temp.Path);
        }
    }

    private TrivyDatabaseStatus InspectDatabase(
        TrivyDatabaseOperation operation,
        bool networkRequested,
        string executablePath,
        string engineVersion,
        string cacheDirectory,
        long durationMs)
    {
        var databaseDirectory = Path.Combine(cacheDirectory, "db");
        var databaseDirectoryValidation = LocalPathPolicy.ValidateLocalDirectoryPath(databaseDirectory);
        if (!databaseDirectoryValidation.IsValid)
        {
            return Status(
                operation,
                TrivyDatabaseState.Invalid,
                networkRequested,
                executablePath,
                engineVersion,
                cacheDirectory,
                null,
                durationMs,
                "trivy_database_path_unsafe",
                "The Trivy database directory is not a safe local directory.");
        }

        if (!Directory.Exists(databaseDirectory))
        {
            return Status(
                operation,
                TrivyDatabaseState.Missing,
                networkRequested,
                executablePath,
                engineVersion,
                cacheDirectory,
                null,
                durationMs,
                "vulnerability_db_missing",
                "The local Trivy vulnerability database is not installed.");
        }

        var metadataPath = Path.Combine(databaseDirectory, "metadata.json");
        var databasePath = Path.Combine(databaseDirectory, "trivy.db");
        var metadataValidation = LocalPathPolicy.ValidateExistingTrivyDatabaseFile(metadataPath);
        var databaseValidation = LocalPathPolicy.ValidateExistingTrivyDatabaseFile(databasePath);
        if (!metadataValidation.IsValid || !databaseValidation.IsValid)
        {
            var missing = metadataValidation.Code == "trivy_database_not_found"
                || databaseValidation.Code == "trivy_database_not_found";
            return Status(
                operation,
                missing ? TrivyDatabaseState.Missing : TrivyDatabaseState.Invalid,
                networkRequested,
                executablePath,
                engineVersion,
                cacheDirectory,
                null,
                durationMs,
                missing ? "vulnerability_db_missing" : "vulnerability_db_invalid",
                missing
                    ? "The local Trivy vulnerability database is incomplete."
                    : "The local Trivy vulnerability database path is unsafe or invalid.");
        }

        DatabaseMetadata metadata;
        try
        {
            var metadataFile = new FileInfo(metadataPath);
            var databaseFile = new FileInfo(databasePath);
            if (metadataFile.Length is <= 0 or > MaximumMetadataBytes || databaseFile.Length <= 0)
            {
                return Status(
                    operation,
                    TrivyDatabaseState.Invalid,
                    networkRequested,
                    executablePath,
                    engineVersion,
                    cacheDirectory,
                    null,
                    durationMs,
                    "vulnerability_db_invalid",
                    "The local Trivy vulnerability database files are empty or malformed.");
            }

            using var document = JsonDocument.Parse(
                File.ReadAllBytes(metadataPath),
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 16,
                });
            metadata = ParseMetadata(document.RootElement);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            return Status(
                operation,
                TrivyDatabaseState.Invalid,
                networkRequested,
                executablePath,
                engineVersion,
                cacheDirectory,
                null,
                durationMs,
                "vulnerability_db_invalid",
                "The local Trivy vulnerability database metadata is invalid or unreadable.");
        }

        var age = timeProvider.GetUtcNow() - metadata.UpdatedAt;
        var ageSeconds = Math.Max(0, (long)age.TotalSeconds);
        if (age < TimeSpan.Zero)
        {
            return Status(
                operation,
                TrivyDatabaseState.Stale,
                networkRequested,
                executablePath,
                engineVersion,
                cacheDirectory,
                metadata,
                durationMs,
                "vulnerability_db_timestamp_future",
                "The local Trivy vulnerability database timestamp is in the future.",
                ageSeconds);
        }

        if (age > MaximumDatabaseAge)
        {
            return Status(
                operation,
                TrivyDatabaseState.Stale,
                networkRequested,
                executablePath,
                engineVersion,
                cacheDirectory,
                metadata,
                durationMs,
                "vulnerability_db_stale",
                "The local Trivy vulnerability database is older than 72 hours.",
                ageSeconds);
        }

        return Status(
            operation,
            TrivyDatabaseState.Ready,
            networkRequested,
            executablePath,
            engineVersion,
            cacheDirectory,
            metadata,
            durationMs,
            "ok",
            networkRequested
                ? "The Trivy database update completed and its local structure and freshness are valid."
                : "The local Trivy vulnerability database is ready.",
            ageSeconds);
    }

    private static DatabaseMetadata ParseMetadata(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !TryGetProperty(root, "Version", out var versionValue)
            || versionValue.ValueKind != JsonValueKind.Number
            || !versionValue.TryGetInt32(out var version)
            || version <= 0)
        {
            throw new InvalidDataException("The database metadata has no valid schema version.");
        }

        if (!TryGetProperty(root, "UpdatedAt", out var updatedValue)
            || updatedValue.ValueKind != JsonValueKind.String
            || !updatedValue.TryGetDateTimeOffset(out var updatedAt))
        {
            throw new InvalidDataException("The database metadata has no valid update time.");
        }

        DateTimeOffset? nextUpdate = null;
        if (TryGetProperty(root, "NextUpdate", out var nextValue)
            && nextValue.ValueKind != JsonValueKind.Null)
        {
            if (nextValue.ValueKind != JsonValueKind.String
                || !nextValue.TryGetDateTimeOffset(out var parsedNextUpdate))
            {
                throw new InvalidDataException("The database metadata has an invalid next-update time.");
            }

            nextUpdate = parsedNextUpdate;
        }

        return new(version, updatedAt, nextUpdate);
    }

    private static bool TryGetProperty(JsonElement element, string name, out JsonElement value)
    {
        if (element.TryGetProperty(name, out value))
        {
            return true;
        }

        var camel = char.ToLowerInvariant(name[0]) + name[1..];
        return element.TryGetProperty(camel, out value);
    }

    private static ProcessInvocation CreateVersionInvocation(
        string executablePath,
        string cacheDirectory,
        string tempDirectory) => new(
        executablePath,
        ["--version"],
        VersionTimeout,
        MaximumVersionOutputCharacters,
        MaximumVersionOutputCharacters,
        RemovedEnvironmentVariables,
        SafeEnvironment(cacheDirectory, tempDirectory, allowNetwork: false),
        RemovedEnvironmentVariablePrefixes);

    private ProcessInvocation CreateUpdateInvocation(
        string executablePath,
        string cacheDirectory,
        string tempDirectory) => new(
        executablePath,
        [
            "image",
            "--download-db-only",
            "--cache-dir", cacheDirectory,
            "--timeout", $"{(long)Math.Ceiling(updateTimeout.TotalSeconds)}s",
            "--skip-java-db-update",
            "--skip-check-update",
            "--skip-vex-repo-update",
            "--skip-version-check",
            "--disable-telemetry",
            "--no-progress",
        ],
        updateTimeout,
        MaximumUpdateOutputCharacters,
        MaximumUpdateOutputCharacters,
        RemovedEnvironmentVariables,
        SafeEnvironment(cacheDirectory, tempDirectory, allowNetwork: true),
        RemovedEnvironmentVariablePrefixes);

    private static ProcessInvocation CreateDatabaseValidationInvocation(
        string executablePath,
        string cacheDirectory,
        string tempDirectory,
        string validationTarget) => new(
        executablePath,
        [
            "filesystem",
            "--scanners", "vuln",
            "--format", "json",
            "--exit-code", "0",
            "--cache-dir", cacheDirectory,
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--skip-vex-repo-update",
            "--offline-scan",
            "--skip-version-check",
            "--disable-telemetry",
            "--no-progress",
            validationTarget,
        ],
        DatabaseValidationTimeout,
        MaximumUpdateOutputCharacters,
        MaximumUpdateOutputCharacters,
        RemovedEnvironmentVariables,
        SafeEnvironment(cacheDirectory, tempDirectory, allowNetwork: false),
        RemovedEnvironmentVariablePrefixes);

    private static TrivyDatabaseStatus ApplyDatabaseValidationResult(
        TrivyDatabaseStatus status,
        ProcessExecutionResult result)
    {
        var durationMs = status.DurationMs + result.DurationMs;
        if (!result.Started)
        {
            return status with
            {
                State = TrivyDatabaseState.Unavailable,
                Ready = false,
                DurationMs = durationMs,
                Code = "trivy_database_validation_unavailable",
                Message = "Trivy could not start the bounded offline database validation.",
            };
        }

        if (result.TimedOut)
        {
            return status with
            {
                State = TrivyDatabaseState.Failed,
                Ready = false,
                DurationMs = durationMs,
                Code = "trivy_database_validation_timeout",
                Message = "Trivy exceeded the bounded offline database-validation timeout.",
            };
        }

        if (result.OutputLimitExceeded)
        {
            return status with
            {
                State = TrivyDatabaseState.Failed,
                Ready = false,
                DurationMs = durationMs,
                Code = "trivy_database_validation_output_too_large",
                Message = "Trivy exceeded the bounded offline database-validation output limit.",
            };
        }

        if (result.ExitCode != 0)
        {
            return status with
            {
                State = TrivyDatabaseState.Invalid,
                Ready = false,
                DurationMs = durationMs,
                Code = "vulnerability_db_unreadable",
                Message = "Trivy could not open and validate the local vulnerability database offline.",
            };
        }

        try
        {
            using var report = JsonDocument.Parse(
                result.StandardOutput,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 32,
                });
            var root = report.RootElement;
            if (!TryGetProperty(root, "SchemaVersion", out var schemaVersion)
                || schemaVersion.ValueKind != JsonValueKind.Number
                || !schemaVersion.TryGetInt32(out var parsedSchemaVersion)
                || parsedSchemaVersion != 2
                || !TryGetProperty(root, "ArtifactType", out var artifactType)
                || artifactType.ValueKind != JsonValueKind.String
                || !string.Equals(artifactType.GetString(), "filesystem", StringComparison.Ordinal))
            {
                throw new InvalidDataException();
            }
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException)
        {
            return status with
            {
                State = TrivyDatabaseState.Invalid,
                Ready = false,
                DurationMs = durationMs,
                Code = "trivy_database_validation_output_invalid",
                Message = "Trivy returned an invalid offline database-validation report.",
            };
        }

        return status with { DurationMs = durationMs };
    }

    private static IReadOnlyDictionary<string, string?> SafeEnvironment(
        string cacheDirectory,
        string tempDirectory,
        bool allowNetwork)
    {
        var environment = new Dictionary<string, string?>
        {
            ["TEMP"] = tempDirectory,
            ["TMP"] = tempDirectory,
            ["NO_COLOR"] = "1",
            ["TRIVY_CACHE_DIR"] = cacheDirectory,
            ["TRIVY_DISABLE_TELEMETRY"] = "true",
            ["TRIVY_SKIP_VERSION_CHECK"] = "true",
            ["TRIVY_SKIP_JAVA_DB_UPDATE"] = "true",
            ["TRIVY_SKIP_CHECK_UPDATE"] = "true",
            ["TRIVY_SKIP_VEX_REPO_UPDATE"] = "true",
        };
        if (!allowNetwork)
        {
            environment["TRIVY_SKIP_DB_UPDATE"] = "true";
            environment["TRIVY_OFFLINE_SCAN"] = "true";
        }

        return environment;
    }

    private static TrivyDatabaseStatus? VersionFailure(
        TrivyDatabaseOperation operation,
        bool networkRequested,
        string executablePath,
        string cacheDirectory,
        ProcessExecutionResult result)
    {
        if (!result.Started)
        {
            return Status(
                operation,
                TrivyDatabaseState.Unavailable,
                networkRequested,
                executablePath,
                null,
                cacheDirectory,
                null,
                result.DurationMs,
                "trivy_unavailable",
                "The validated Trivy executable could not be started.");
        }

        if (result.TimedOut)
        {
            return Status(
                operation,
                TrivyDatabaseState.Unavailable,
                networkRequested,
                executablePath,
                null,
                cacheDirectory,
                null,
                result.DurationMs,
                "trivy_version_timeout",
                "Trivy exceeded the ten-second version check limit.");
        }

        if (result.OutputLimitExceeded)
        {
            return Status(
                operation,
                TrivyDatabaseState.Unavailable,
                networkRequested,
                executablePath,
                null,
                cacheDirectory,
                null,
                result.DurationMs,
                "trivy_version_output_too_large",
                "Trivy exceeded the bounded version output limit.");
        }

        return result.ExitCode == 0
            ? null
            : Status(
                operation,
                TrivyDatabaseState.Unavailable,
                networkRequested,
                executablePath,
                null,
                cacheDirectory,
                null,
                result.DurationMs,
                "trivy_version_failed",
                "Trivy could not report its version successfully.");
    }

    private static TrivyDatabaseStatus? UpdateFailure(
        TrivyDatabaseOperation operation,
        string executablePath,
        string engineVersion,
        string cacheDirectory,
        long durationMs,
        ProcessExecutionResult result)
    {
        if (!result.Started)
        {
            return Status(
                operation,
                TrivyDatabaseState.Failed,
                true,
                executablePath,
                engineVersion,
                cacheDirectory,
                null,
                durationMs,
                "trivy_update_unavailable",
                "Trivy could not start the explicit database update.");
        }

        if (result.TimedOut)
        {
            return Status(
                operation,
                TrivyDatabaseState.Failed,
                true,
                executablePath,
                engineVersion,
                cacheDirectory,
                null,
                durationMs,
                "trivy_update_timeout",
                "Trivy exceeded the bounded database update limit.");
        }

        if (result.OutputLimitExceeded)
        {
            return Status(
                operation,
                TrivyDatabaseState.Failed,
                true,
                executablePath,
                engineVersion,
                cacheDirectory,
                null,
                durationMs,
                "trivy_update_output_too_large",
                "Trivy exceeded the bounded database update output limit.");
        }

        return result.ExitCode == 0
            ? null
            : Status(
                operation,
                TrivyDatabaseState.Failed,
                true,
                executablePath,
                engineVersion,
                cacheDirectory,
                null,
                durationMs,
                "trivy_update_failed",
                "Trivy did not complete the explicit database update.");
    }

    private TempDirectoryResult CreateInvocationTempDirectory()
    {
        var rootValidation = LocalPathPolicy.ValidateLocalDirectoryPath(tempRootDirectory);
        if (!rootValidation.IsValid)
        {
            return new(null);
        }

        try
        {
            var root = rootValidation.FullPath!;
            Directory.CreateDirectory(root);
            rootValidation = LocalPathPolicy.ValidateLocalDirectoryPath(root);
            if (!rootValidation.IsValid)
            {
                return new(null);
            }

            var path = Path.Combine(root, $"db-{Guid.NewGuid():N}");
            Directory.CreateDirectory(path);
            var validation = LocalPathPolicy.ValidateLocalDirectoryPath(path);
            if (!validation.IsValid)
            {
                TryDeleteInvocationTempDirectory(root, path);
                return new(null);
            }

            return new(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new(null);
        }
    }

    private static string? CreateDatabaseValidationTarget(string tempDirectory)
    {
        try
        {
            var target = Path.Combine(tempDirectory, "database-validation-target");
            Directory.CreateDirectory(target);
            var validation = LocalPathPolicy.ValidateLocalDirectoryPath(target);
            if (!validation.IsValid || Directory.EnumerateFileSystemEntries(target).Any())
            {
                return null;
            }

            return validation.FullPath;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    internal static bool TryDeleteInvocationTempDirectory(string root, string candidate)
    {
        try
        {
            var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var fullCandidate = Path.GetFullPath(candidate)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (!string.Equals(Path.GetDirectoryName(fullCandidate), fullRoot, StringComparison.OrdinalIgnoreCase)
                || !InvocationTempNameRegex().IsMatch(Path.GetFileName(fullCandidate)))
            {
                return false;
            }

            if (Directory.Exists(fullCandidate))
            {
                var reparse = LocalPathPolicy.IsReparsePoint(File.GetAttributes(fullCandidate));
                Directory.Delete(fullCandidate, recursive: !reparse);
            }

            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static TrivyDatabaseStatus Status(
        TrivyDatabaseOperation operation,
        TrivyDatabaseState state,
        bool networkRequested,
        string? executablePath,
        string? engineVersion,
        string? cacheDirectory,
        DatabaseMetadata? metadata,
        long durationMs,
        string code,
        string message,
        long? ageSeconds = null) => new(
        StatusSchemaVersion,
        "trivy",
        operation,
        state,
        state == TrivyDatabaseState.Ready,
        networkRequested,
        executablePath,
        engineVersion,
        cacheDirectory,
        metadata?.Version,
        metadata?.UpdatedAt,
        metadata?.NextUpdate,
        ageSeconds,
        (long)MaximumDatabaseAge.TotalSeconds,
        durationMs,
        code,
        message);

    private static string? ParseEngineVersion(string output)
    {
        var match = EngineVersionRegex().Match(output);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static string? SafeFullPath(string path)
    {
        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    private static string ResolveCacheDirectory()
    {
        var configured = Environment.GetEnvironmentVariable("PORTCVE_TRIVY_CACHE_DIR")
            ?? Environment.GetEnvironmentVariable("TRIVY_CACHE_DIR");
        return !string.IsNullOrWhiteSpace(configured)
            ? configured
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "trivy");
    }

    private static string ResolveTempRootDirectory() => Path.Combine(
        Path.GetTempPath(),
        "PortCVE",
        "trivy-db");

    private sealed record DatabaseMetadata(
        int Version,
        DateTimeOffset UpdatedAt,
        DateTimeOffset? NextUpdate);

    private sealed record TempDirectoryResult(string? Path);

    [GeneratedRegex("^db-[0-9a-f]{32}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex InvocationTempNameRegex();

    [GeneratedRegex(
        @"(?im)^Version:\s*([0-9A-Za-z][0-9A-Za-z.+-]{0,63})\s*$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex EngineVersionRegex();
}
