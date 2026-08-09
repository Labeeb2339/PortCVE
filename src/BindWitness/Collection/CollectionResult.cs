using BindWitness.Domain;

namespace BindWitness.Collection;

public sealed record CollectionResult<T>(
    T Value,
    CollectorReport Report)
{
    public static CollectionResult<T> Complete(string name, DateTimeOffset observedAt, long durationMs, T value) =>
        new(value, new(name, CollectorStatus.Complete, observedAt, durationMs, []));
}
