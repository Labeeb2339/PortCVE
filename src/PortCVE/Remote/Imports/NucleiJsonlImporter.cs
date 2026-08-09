using System.Globalization;
using System.Text;
using System.Text.Json;

namespace PortCVE.Remote.Imports;

internal static class NucleiJsonlImporter
{
    private const int MaximumRecords = 100000;
    private const int MaximumPhysicalLines = 200000;
    private const int MaximumRecordBytes = 1024 * 1024;
    private const int ReadBufferBytes = 64 * 1024;
    private const long MaximumRetainedCharacters = 16L * 1024 * 1024;

    private static readonly UTF8Encoding StrictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static PentestImportReport Import(
        Stream stream,
        bool strict = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
        {
            throw new ArgumentException("Nuclei JSONL input must be readable.", nameof(stream));
        }

        var findings = new List<ImportedFinding>();
        var diagnostics = new List<PentestImportDiagnostic>();
        var retentionBudget = new ImportRetentionBudget(MaximumRetainedCharacters);
        var readBuffer = new byte[ReadBufferBytes];
        using var recordBuffer = new MemoryStream(capacity: 64 * 1024);
        var physicalLines = 0;
        var recordCount = 0;
        var recordTooLarge = false;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var bytesRead = stream.Read(readBuffer, 0, readBuffer.Length);
            if (bytesRead == 0)
            {
                break;
            }

            var remaining = readBuffer.AsSpan(0, bytesRead);
            while (!remaining.IsEmpty)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var newline = remaining.IndexOf((byte)'\n');
                var segment = newline >= 0 ? remaining[..newline] : remaining;
                AppendSegment(
                    segment,
                    recordBuffer,
                    ref recordTooLarge,
                    strict,
                    diagnostics,
                    physicalLines + 1,
                    retentionBudget);

                if (newline < 0)
                {
                    break;
                }

                physicalLines++;
                EnforcePhysicalLineLimit(physicalLines);
                ProcessRecord(
                    recordBuffer,
                    recordTooLarge,
                    strict,
                    physicalLines,
                    ref recordCount,
                    findings,
                    diagnostics,
                    retentionBudget,
                    cancellationToken);
                recordBuffer.SetLength(0);
                recordTooLarge = false;
                remaining = remaining[(newline + 1)..];
            }
        }

        if (recordBuffer.Length > 0 || recordTooLarge)
        {
            physicalLines++;
            EnforcePhysicalLineLimit(physicalLines);
            ProcessRecord(
                recordBuffer,
                recordTooLarge,
                strict,
                physicalLines,
                ref recordCount,
                findings,
                diagnostics,
                retentionBudget,
                cancellationToken);
        }

        return new(
            "nuclei_jsonl",
            null,
            diagnostics.Count == 0,
            [],
            findings.OrderBy(static item => item.Target, StringComparer.Ordinal)
                .ThenBy(static item => item.Port)
                .ThenBy(static item => item.FindingId, StringComparer.Ordinal)
                .ToArray(),
            diagnostics);
    }

    private static void AppendSegment(
        ReadOnlySpan<byte> segment,
        MemoryStream recordBuffer,
        ref bool recordTooLarge,
        bool strict,
        ICollection<PentestImportDiagnostic> diagnostics,
        int lineNumber,
        ImportRetentionBudget retentionBudget)
    {
        if (recordTooLarge || segment.IsEmpty)
        {
            return;
        }

        if (recordBuffer.Length + segment.Length > MaximumRecordBytes)
        {
            recordBuffer.SetLength(0);
            recordTooLarge = true;
            if (strict)
            {
                HandleInvalid(
                    strict,
                    diagnostics,
                    lineNumber,
                    "Nuclei JSONL record exceeds the 1 MiB UTF-8 byte limit.",
                    retentionBudget);
            }

            return;
        }

        recordBuffer.Write(segment);
    }

    private static void ProcessRecord(
        MemoryStream recordBuffer,
        bool recordTooLarge,
        bool strict,
        int lineNumber,
        ref int recordCount,
        ICollection<ImportedFinding> findings,
        ICollection<PentestImportDiagnostic> diagnostics,
        ImportRetentionBudget retentionBudget,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (recordTooLarge)
        {
            recordCount++;
            EnforceRecordLimit(recordCount);
            HandleInvalid(
                strict,
                diagnostics,
                lineNumber,
                "Nuclei JSONL record exceeds the 1 MiB UTF-8 byte limit.",
                retentionBudget);
            return;
        }

        var length = checked((int)recordBuffer.Length);
        var bytes = recordBuffer.GetBuffer().AsSpan(0, length);
        if (bytes.EndsWith("\r"u8))
        {
            bytes = bytes[..^1];
        }

        if (lineNumber == 1 && bytes.StartsWith(Encoding.UTF8.Preamble))
        {
            bytes = bytes[Encoding.UTF8.Preamble.Length..];
        }

        var line = StrictUtf8.GetString(bytes);
        if (string.IsNullOrWhiteSpace(line))
        {
            return;
        }

        recordCount++;
        EnforceRecordLimit(recordCount);
        try
        {
            var finding = ParseRecord(line, ImportText.Sha256(bytes));
            if (finding is not null)
            {
                retentionBudget.Reserve(FindingCharacters(finding));
                findings.Add(finding);
            }
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException)
        {
            HandleInvalid(strict, diagnostics, lineNumber, exception.Message, retentionBudget);
        }
    }

    private static ImportedFinding? ParseRecord(string line, string sourceRecordSha256)
    {
        using var document = JsonDocument.Parse(line, new() { MaxDepth = 64 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("Nuclei JSONL record must be an object.");
        }

        if (root.TryGetProperty("matcher-status", out var matcherStatus))
        {
            if (matcherStatus.ValueKind == JsonValueKind.False)
            {
                return null;
            }

            if (matcherStatus.ValueKind != JsonValueKind.True)
            {
                throw new InvalidDataException("Nuclei JSONL matcher-status must be a boolean when present.");
            }
        }

        var templateId = RequiredIdentifier(root, "template-id", 256);
        if (!root.TryGetProperty("info", out var info) || info.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("Nuclei JSONL record is missing its info object.");
        }

        var title = ImportText.SanitizePublicLabel(OptionalString(info, "name", 512), 512) ?? templateId;
        var severity = (OptionalString(info, "severity", 32) ?? "unknown").ToLowerInvariant();
        if (severity is not "info" and not "low" and not "medium" and not "high" and not "critical" and not "unknown")
        {
            severity = "unknown";
        }

        var rawTarget = OptionalString(root, "matched-at", 2048)
            ?? OptionalString(root, "host", 2048)
            ?? throw new InvalidDataException("Nuclei JSONL record has no matched-at or host target.");
        var target = ImportText.SanitizeTarget(rawTarget)
            ?? throw new InvalidDataException("Nuclei JSONL target could not be reduced to safe endpoint metadata.");
        var protocol = ImportText.SanitizeIdentifier(
            OptionalString(root, "scheme", 32) ?? OptionalString(root, "type", 64),
            64)?.ToLowerInvariant();
        int? port = null;
        if (root.TryGetProperty("port", out var portElement))
        {
            if (portElement.ValueKind == JsonValueKind.Number && portElement.TryGetInt32(out var numericPort))
            {
                port = numericPort is >= 1 and <= 65535 ? numericPort : null;
            }
            else if (portElement.ValueKind == JsonValueKind.String
                && int.TryParse(portElement.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out numericPort))
            {
                port = numericPort is >= 1 and <= 65535 ? numericPort : null;
            }
        }

        var advisoryIds = new SortedSet<string>(StringComparer.Ordinal);
        var references = new SortedSet<string>(StringComparer.Ordinal);
        if (info.TryGetProperty("classification", out var classification) && classification.ValueKind == JsonValueKind.Object)
        {
            AddAdvisoryIds(classification, "cve-id", advisoryIds, 64);
        }

        AddReferences(info, "reference", references, 32);
        var matcher = ImportText.SanitizeIdentifier(OptionalString(root, "matcher-name", 256), 256);
        return new(
            "nuclei_jsonl",
            templateId,
            title,
            severity,
            target,
            port,
            protocol,
            ImportedClaimStatus.ImportedMatch,
            ImportedEvidenceStrength.Unresolved,
            advisoryIds.ToArray(),
            references.ToArray(),
            sourceRecordSha256,
            matcher,
            null);
    }

    private static void AddAdvisoryIds(
        JsonElement parent,
        string property,
        ISet<string> destination,
        int maximumItems)
    {
        AddSanitizedStrings(parent, property, destination, maximumItems, static value =>
        {
            var candidate = ImportText.SanitizeIdentifier(value, 64)?.ToUpperInvariant();
            if (candidate is null || !candidate.StartsWith("CVE-", StringComparison.Ordinal)
                || candidate.Length < 13
                || !ContainsOnlyAsciiDigits(candidate.AsSpan(4, 4))
                || candidate[8] != '-'
                || !ContainsOnlyAsciiDigits(candidate.AsSpan(9)))
            {
                return null;
            }

            return candidate;
        });
    }

    private static void AddReferences(
        JsonElement parent,
        string property,
        ISet<string> destination,
        int maximumItems) =>
        AddSanitizedStrings(parent, property, destination, maximumItems, ImportText.SanitizeReference);

    private static void AddSanitizedStrings(
        JsonElement parent,
        string property,
        ISet<string> destination,
        int maximumItems,
        Func<string?, string?> sanitizer)
    {
        if (!parent.TryGetProperty(property, out var element))
        {
            return;
        }

        if (element.ValueKind == JsonValueKind.String)
        {
            var value = sanitizer(element.GetString());
            if (value is not null)
            {
                destination.Add(value);
            }

            return;
        }

        if (element.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var item in element.EnumerateArray())
        {
            if (destination.Count >= maximumItems)
            {
                return;
            }

            if (item.ValueKind == JsonValueKind.String)
            {
                var value = sanitizer(item.GetString());
                if (value is not null)
                {
                    destination.Add(value);
                }
            }
        }
    }

    private static string RequiredIdentifier(JsonElement parent, string property, int maximumCharacters)
    {
        var raw = OptionalString(parent, property, maximumCharacters);
        return ImportText.SanitizeIdentifier(raw, maximumCharacters)
            ?? throw new InvalidDataException($"Nuclei JSONL record has no safe '{property}' identifier.");
    }

    private static bool ContainsOnlyAsciiDigits(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    private static long FindingCharacters(ImportedFinding finding) =>
        ImportRetentionBudget.Characters(
            finding.Source,
            finding.FindingId,
            finding.Title,
            finding.Severity,
            finding.Target,
            finding.Protocol,
            finding.SourceRecordSha256,
            finding.Matcher,
            finding.Summary)
        + ImportRetentionBudget.Characters(finding.AdvisoryIds)
        + ImportRetentionBudget.Characters(finding.References);

    private static string? OptionalString(JsonElement parent, string property, int maximumCharacters)
    {
        if (!parent.TryGetProperty(property, out var element) || element.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return ImportText.Sanitize(element.GetString(), maximumCharacters);
    }

    private static void EnforcePhysicalLineLimit(int physicalLines)
    {
        if (physicalLines > MaximumPhysicalLines)
        {
            throw new InvalidDataException($"Nuclei JSONL exceeds the {MaximumPhysicalLines} physical-line import limit.");
        }
    }

    private static void EnforceRecordLimit(int recordCount)
    {
        if (recordCount > MaximumRecords)
        {
            throw new InvalidDataException($"Nuclei JSONL exceeds the {MaximumRecords} record import limit.");
        }
    }

    private static void HandleInvalid(
        bool strict,
        ICollection<PentestImportDiagnostic> diagnostics,
        int lineNumber,
        string message,
        ImportRetentionBudget retentionBudget)
    {
        if (strict)
        {
            throw new InvalidDataException($"Invalid Nuclei JSONL at line {lineNumber}: {message}");
        }

        var safeMessage = ImportText.SanitizePublicLabel(message, 512) ?? "The record was invalid.";
        var diagnostic = new PentestImportDiagnostic("nuclei_record_invalid", $"Line {lineNumber}: {safeMessage}");
        retentionBudget.Reserve(ImportRetentionBudget.Characters(diagnostic.Code, diagnostic.Message));
        diagnostics.Add(diagnostic);
    }
}
