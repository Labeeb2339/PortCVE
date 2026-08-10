namespace PortCVE.Vulnerabilities;

internal sealed record TrivyDatabaseDocument(
    int SchemaVersion,
    string ToolVersion,
    string Provider,
    TrivyDatabaseOperation Operation,
    TrivyDatabaseState State,
    bool Ready,
    bool NetworkRequested,
    string PrivacyMode,
    string ExecutablePath,
    string? EngineVersion,
    string CacheDirectory,
    int? DatabaseSchemaVersion,
    DateTimeOffset? DatabaseUpdatedAt,
    DateTimeOffset? DatabaseNextUpdate,
    long? DatabaseAgeSeconds,
    long MaximumDatabaseAgeSeconds,
    long DurationMs,
    string Code,
    string Message)
{
    internal const int CurrentSchemaVersion = 1;
    internal const string PrivateMode = "private";
    internal const string ReducedMode = "reduced";
    internal const string UnresolvedPath = "unresolved";

    public static TrivyDatabaseDocument FromStatus(
        TrivyDatabaseStatus status,
        string toolVersion) => new(
        CurrentSchemaVersion,
        toolVersion,
        status.Provider,
        status.Operation,
        status.State,
        status.Ready,
        status.NetworkRequested,
        PrivateMode,
        status.ExecutablePath ?? UnresolvedPath,
        status.EngineVersion,
        status.CacheDirectory ?? UnresolvedPath,
        status.DatabaseSchemaVersion,
        status.DatabaseUpdatedAt,
        status.DatabaseNextUpdate,
        status.DatabaseAgeSeconds,
        status.MaximumDatabaseAgeSeconds,
        status.DurationMs,
        status.Code,
        status.Message);
}

internal static class TrivyDatabaseDocumentRedactor
{
    internal const string ExecutableAlias = "local-trivy-executable";
    internal const string CacheAlias = "local-trivy-cache";

    public static TrivyDatabaseDocument Redact(TrivyDatabaseDocument document) => document with
    {
        PrivacyMode = TrivyDatabaseDocument.ReducedMode,
        ExecutablePath = RedactPath(document.ExecutablePath, ExecutableAlias),
        CacheDirectory = RedactPath(document.CacheDirectory, CacheAlias),
        Message = RedactMessage(document),
    };

    private static string RedactPath(string path, string alias) =>
        path == TrivyDatabaseDocument.UnresolvedPath ? path : alias;

    private static string RedactMessage(TrivyDatabaseDocument document)
    {
        var result = document.Message;
        foreach (var item in new[]
                 {
                     (Path: document.ExecutablePath, Alias: ExecutableAlias),
                     (Path: document.CacheDirectory, Alias: CacheAlias),
                 }
                 .Where(static item => item.Path != TrivyDatabaseDocument.UnresolvedPath)
                 .OrderByDescending(static item => item.Path.Length))
        {
            result = result.Replace(item.Path, item.Alias, StringComparison.OrdinalIgnoreCase);
        }

        return result;
    }
}
