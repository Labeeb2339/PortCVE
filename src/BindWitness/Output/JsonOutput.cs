using System.Text.Json;
using System.Text.Json.Serialization;

namespace BindWitness.Output;

public static class JsonOutput
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower, allowIntegerValues: false) },
    };

    public static string Serialize<T>(T value, bool indented = true)
    {
        if (indented)
        {
            return JsonSerializer.Serialize(value, Options);
        }

        var compact = new JsonSerializerOptions(Options) { WriteIndented = false };
        return JsonSerializer.Serialize(value, compact);
    }
}
