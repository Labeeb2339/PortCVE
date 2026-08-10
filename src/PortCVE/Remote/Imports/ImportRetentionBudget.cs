namespace PortCVE.Remote.Imports;

internal sealed class ImportRetentionBudget(long maximumCharacters)
{
    private long retainedCharacters;

    public void Reserve(long characters)
    {
        if (characters < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(characters));
        }

        if (characters > maximumCharacters - retainedCharacters)
        {
            throw new InvalidDataException(
                $"Normalized import output exceeds the {maximumCharacters / (1024 * 1024)} MiB retained-character limit.");
        }

        retainedCharacters += characters;
    }

    public static long Characters(params string?[] values) =>
        values.Sum(static value => (long)(value?.Length ?? 0));

    public static long Characters(IEnumerable<string> values) =>
        values.Sum(static value => (long)value.Length);
}
