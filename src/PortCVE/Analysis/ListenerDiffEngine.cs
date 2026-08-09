using PortCVE.Domain;
using PortCVE.Snapshots;

namespace PortCVE.Analysis;

public enum ListenerChangeKind
{
    Added,
    Removed,
    OwnerChanged,
    ExposureExpanded,
    ExposureNarrowed,
    PolicyChanged,
    EvidenceRegressed,
    EvidenceImproved,
}

public sealed record ListenerChange(
    ListenerChangeKind Kind,
    string Key,
    LockedListener? Before,
    LockedListener? After,
    string Summary);

public static class ListenerDiffEngine
{
    public static IReadOnlyList<ListenerChange> CompareEvidence(
        LockfileEvidence before,
        LockfileEvidence after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);

        var changes = new List<ListenerChange>();
        CompareEvidenceField("ownership", before.Ownership, after.Ownership, changes);
        CompareEvidenceField("bind_scope", before.BindScope, after.BindScope, changes);
        CompareEvidenceField("host_policy", before.HostPolicy, after.HostPolicy, changes);
        CompareEvidenceField("containers", before.Containers, after.Containers, changes);
        return changes;
    }

    public static IReadOnlyList<ListenerChange> Compare(
        IReadOnlyList<LockedListener> before,
        IReadOnlyList<LockedListener> after)
    {
        var changes = new List<ListenerChange>();
        var oldGroups = before.GroupBy(static item => item.Key, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.ToList(), StringComparer.Ordinal);
        var newGroups = after.GroupBy(static item => item.Key, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.ToList(), StringComparer.Ordinal);

        foreach (var key in oldGroups.Keys.Union(newGroups.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            var oldItems = oldGroups.GetValueOrDefault(key) ?? [];
            var newItems = newGroups.GetValueOrDefault(key) ?? [];
            var unmatchedOld = oldItems.OrderBy(StableIdentity, StringComparer.Ordinal).ToList();
            var unmatchedNew = newItems.OrderBy(StableIdentity, StringComparer.Ordinal).ToList();

            // Remove exact matches first so legitimate shared/reused UDP binds are compared as a multiset.
            for (var oldIndex = unmatchedOld.Count - 1; oldIndex >= 0; oldIndex--)
            {
                var exactIndex = unmatchedNew.FindIndex(item => item == unmatchedOld[oldIndex]);
                if (exactIndex >= 0)
                {
                    unmatchedOld.RemoveAt(oldIndex);
                    unmatchedNew.RemoveAt(exactIndex);
                }
            }

            while (unmatchedOld.Count > 0 && unmatchedNew.Count > 0)
            {
                var oldItem = unmatchedOld[0];
                var preferredIndex = unmatchedNew.FindIndex(item =>
                    string.Equals(item.OwnerIdentity, oldItem.OwnerIdentity, StringComparison.OrdinalIgnoreCase));
                if (preferredIndex < 0)
                {
                    preferredIndex = 0;
                }

                var newItem = unmatchedNew[preferredIndex];
                unmatchedOld.RemoveAt(0);
                unmatchedNew.RemoveAt(preferredIndex);
                ComparePair(key, oldItem, newItem, changes);
            }

            foreach (var oldItem in unmatchedOld)
            {
                changes.Add(new(ListenerChangeKind.Removed, key, oldItem, null, "expected endpoint is absent"));
            }

            foreach (var newItem in unmatchedNew)
            {
                changes.Add(new(ListenerChangeKind.Added, key, null, newItem, "new local endpoint"));
            }
        }

        return CoalesceBindScopeChanges(changes)
            .OrderBy(static change => change.Key, StringComparer.Ordinal)
            .ThenBy(static change => change.Kind)
            .ToArray();
    }

    private static IReadOnlyList<ListenerChange> CoalesceBindScopeChanges(List<ListenerChange> changes)
    {
        var removed = changes.Where(static change => change.Kind == ListenerChangeKind.Removed).ToList();
        var added = changes.Where(static change => change.Kind == ListenerChangeKind.Added).ToList();

        foreach (var oldChange in removed.ToArray())
        {
            var oldItem = oldChange.Before!;
            var newChange = added.FirstOrDefault(candidate =>
                candidate.After!.Protocol == oldItem.Protocol
                && candidate.After.Family == oldItem.Family
                && candidate.After.Port == oldItem.Port
                && string.Equals(candidate.After.OwnerIdentity, oldItem.OwnerIdentity, StringComparison.OrdinalIgnoreCase)
                && candidate.After.Scope != oldItem.Scope);
            if (newChange is null)
            {
                continue;
            }

            var newItem = newChange.After!;
            changes.Remove(oldChange);
            changes.Remove(newChange);
            added.Remove(newChange);

            var kind = newItem.Scope == BindScope.Unknown
                ? ListenerChangeKind.EvidenceRegressed
                : oldItem.Scope == BindScope.Unknown
                    ? ListenerChangeKind.EvidenceImproved
                    : ExposureRank(newItem.Scope) > ExposureRank(oldItem.Scope)
                        ? ListenerChangeKind.ExposureExpanded
                        : ListenerChangeKind.ExposureNarrowed;
            changes.Add(new(
                kind,
                newItem.Key,
                oldItem,
                newItem,
                kind == ListenerChangeKind.EvidenceRegressed
                    ? $"bind-scope evidence regressed from {oldItem.Scope} to unknown"
                    : kind == ListenerChangeKind.EvidenceImproved
                        ? $"bind-scope evidence improved from unknown to {newItem.Scope}"
                        : $"bind changed from {oldItem.Address} ({oldItem.Scope}) to {newItem.Address} ({newItem.Scope})"));

            if (PolicyEvidenceRank(newItem) < PolicyEvidenceRank(oldItem))
            {
                changes.Add(new(
                    ListenerChangeKind.EvidenceRegressed,
                    newItem.Key,
                    oldItem,
                    newItem,
                    $"host-policy evidence regressed from {oldItem.HostPolicy} to {newItem.HostPolicy}"));
            }
            else if (PolicyEvidenceRank(newItem) > PolicyEvidenceRank(oldItem))
            {
                changes.Add(new(
                    ListenerChangeKind.EvidenceImproved,
                    newItem.Key,
                    oldItem,
                    newItem,
                    $"host-policy evidence improved from {oldItem.HostPolicy} to {newItem.HostPolicy}"));
            }
            else if (oldItem.HostPolicy != newItem.HostPolicy)
            {
                changes.Add(new(
                    ListenerChangeKind.PolicyChanged,
                    newItem.Key,
                    oldItem,
                    newItem,
                    $"host policy changed from {oldItem.HostPolicy} to {newItem.HostPolicy}"));
            }
        }

        return changes;
    }

    private static void ComparePair(
        string key,
        LockedListener oldItem,
        LockedListener newItem,
        ICollection<ListenerChange> changes)
    {
        if (oldItem.OwnerIdentityStrength == OwnerIdentityStrength.ContainerImage
            && newItem.OwnerIdentityStrength != OwnerIdentityStrength.ContainerImage)
        {
            changes.Add(new(ListenerChangeKind.OwnerChanged, key, oldItem, newItem,
                $"container-backed owner changed from {oldItem.OwnerIdentity} to {newItem.OwnerIdentity}"));
        }
        else if (OwnerStrengthRank(newItem.OwnerIdentityStrength) < OwnerStrengthRank(oldItem.OwnerIdentityStrength))
        {
            changes.Add(new(ListenerChangeKind.EvidenceRegressed, key, oldItem, newItem,
                $"owner evidence regressed from {oldItem.OwnerIdentityStrength} to {newItem.OwnerIdentityStrength}"));
        }
        else if (!string.Equals(oldItem.OwnerIdentity, newItem.OwnerIdentity, StringComparison.OrdinalIgnoreCase))
        {
            changes.Add(new(ListenerChangeKind.OwnerChanged, key, oldItem, newItem,
                $"owner changed from {oldItem.OwnerIdentity} to {newItem.OwnerIdentity}"));
        }

        if (oldItem.Scope != newItem.Scope && newItem.Scope == BindScope.Unknown)
        {
            changes.Add(new(ListenerChangeKind.EvidenceRegressed, key, oldItem, newItem,
                $"bind-scope evidence regressed from {oldItem.Scope} to unknown"));
        }
        else if (oldItem.Scope != newItem.Scope && oldItem.Scope == BindScope.Unknown)
        {
            changes.Add(new(ListenerChangeKind.EvidenceImproved, key, oldItem, newItem,
                $"bind-scope evidence improved from unknown to {newItem.Scope}"));
        }
        else if (ExposureRank(newItem.Scope) > ExposureRank(oldItem.Scope))
        {
            changes.Add(new(ListenerChangeKind.ExposureExpanded, key, oldItem, newItem,
                $"bind scope expanded from {oldItem.Scope} to {newItem.Scope}"));
        }
        else if (ExposureRank(newItem.Scope) < ExposureRank(oldItem.Scope))
        {
            changes.Add(new(ListenerChangeKind.ExposureNarrowed, key, oldItem, newItem,
                $"bind scope narrowed from {oldItem.Scope} to {newItem.Scope}"));
        }

        if (PolicyEvidenceRank(newItem) < PolicyEvidenceRank(oldItem))
        {
            changes.Add(new(ListenerChangeKind.EvidenceRegressed, key, oldItem, newItem,
                $"host-policy evidence regressed from {oldItem.HostPolicy} to {newItem.HostPolicy}"));
        }
        else if (PolicyEvidenceRank(newItem) > PolicyEvidenceRank(oldItem))
        {
            changes.Add(new(ListenerChangeKind.EvidenceImproved, key, oldItem, newItem,
                $"host-policy evidence improved from {oldItem.HostPolicy} to {newItem.HostPolicy}"));
        }
        else if (oldItem.HostPolicy != newItem.HostPolicy)
        {
            changes.Add(new(ListenerChangeKind.PolicyChanged, key, oldItem, newItem,
                $"host policy changed from {oldItem.HostPolicy} to {newItem.HostPolicy}"));
        }
    }

    private static string StableIdentity(LockedListener item) =>
        $"{item.OwnerIdentity}\0{item.OwnerIdentityStrength}\0{item.Scope}\0{item.HostPolicy}\0{item.HostPolicyConfidence}";

    private static void CompareEvidenceField(
        string name,
        EvidenceCompleteness before,
        EvidenceCompleteness after,
        ICollection<ListenerChange> changes)
    {
        if (before == after)
        {
            return;
        }

        var kind = EvidenceRank(after) < EvidenceRank(before)
            ? ListenerChangeKind.EvidenceRegressed
            : ListenerChangeKind.EvidenceImproved;
        changes.Add(new(
            kind,
            $"evidence/{name}",
            null,
            null,
            $"{name.Replace('_', '-')} evidence {kind switch
            {
                ListenerChangeKind.EvidenceRegressed => "regressed",
                _ => "improved",
            }} from {before} to {after}"));
    }

    private static int EvidenceRank(EvidenceCompleteness completeness) => completeness switch
    {
        EvidenceCompleteness.Complete => 2,
        EvidenceCompleteness.Partial => 1,
        EvidenceCompleteness.NotCollected => 0,
        _ => 0,
    };

    private static int ExposureRank(BindScope scope) => scope switch
    {
        BindScope.Loopback => 0,
        BindScope.Interface => 1,
        BindScope.Wildcard => 2,
        _ => -1,
    };

    private static int OwnerStrengthRank(OwnerIdentityStrength strength) => strength switch
    {
        OwnerIdentityStrength.Unknown => 0,
        OwnerIdentityStrength.NameOnly => 1,
        OwnerIdentityStrength.Service or OwnerIdentityStrength.Kernel => 2,
        OwnerIdentityStrength.Sha256 or OwnerIdentityStrength.ContainerImage => 3,
        _ => 0,
    };

    private static int PolicyEvidenceRank(LockedListener listener) => listener.HostPolicy switch
    {
        FirewallVerdict.NotEvaluated or FirewallVerdict.Unknown => 0,
        FirewallVerdict.Mixed => 1,
        FirewallVerdict.Allow or FirewallVerdict.Block or FirewallVerdict.Disabled
            when listener.HostPolicyConfidence == Confidence.Low => 1,
        FirewallVerdict.Allow or FirewallVerdict.Block or FirewallVerdict.Disabled => 2,
        _ => 0,
    };
}
