using System.Globalization;
using System.Text;

namespace PortCVE.Remote;

internal static class RemoteEvidenceSanitizer
{
    public static string Sanitize(ReadOnlySpan<byte> bytes, int maximumUtf8Bytes) =>
        Sanitize(Encoding.UTF8.GetString(bytes), maximumUtf8Bytes);

    public static string Sanitize(string? value, int maximumUtf8Bytes)
    {
        if (string.IsNullOrEmpty(value) || maximumUtf8Bytes <= 0)
        {
            return string.Empty;
        }

        var result = new StringBuilder(Math.Min(value.Length, maximumUtf8Bytes));
        var wasWhitespace = false;
        foreach (var rune in value.EnumerateRunes())
        {
            var category = Rune.GetUnicodeCategory(rune);
            var isUnsafe = category is UnicodeCategory.Control
                or UnicodeCategory.Format
                or UnicodeCategory.LineSeparator
                or UnicodeCategory.ParagraphSeparator
                or UnicodeCategory.Surrogate;
            var isLineWhitespace = rune.Value is '\r' or '\n' or '\t';
            if (isUnsafe && !isLineWhitespace)
            {
                result.Append('\uFFFD');
                wasWhitespace = false;
                continue;
            }

            var isWhitespace = isLineWhitespace || Rune.IsWhiteSpace(rune);
            if (isWhitespace)
            {
                if (!wasWhitespace && result.Length > 0)
                {
                    result.Append(' ');
                }

                wasWhitespace = true;
                continue;
            }

            result.Append(rune);
            wasWhitespace = false;
        }

        return TruncateUtf8(result.ToString().Trim(), maximumUtf8Bytes);
    }

    private static string TruncateUtf8(string value, int maximumUtf8Bytes)
    {
        if (Encoding.UTF8.GetByteCount(value) <= maximumUtf8Bytes)
        {
            return value;
        }

        var result = new StringBuilder(value.Length);
        var usedBytes = 0;
        foreach (var rune in value.EnumerateRunes())
        {
            if (usedBytes + rune.Utf8SequenceLength > maximumUtf8Bytes)
            {
                break;
            }

            result.Append(rune);
            usedBytes += rune.Utf8SequenceLength;
        }

        return result.ToString().TrimEnd();
    }
}
