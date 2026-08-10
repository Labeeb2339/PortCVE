using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text.Json;
using PortCVE.Domain;

namespace PortCVE.Collection;

public sealed record FirewallCollection(
    WindowsFirewallPolicy? Policy,
    CollectorReport Report);

public sealed class WindowsFirewallCollector
{
    private const string FirewallScript = """
        $ErrorActionPreference = 'Stop'

        $rules = @(
          Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -ErrorAction Stop
        )

        $profiles = @(
          Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
            ForEach-Object {
              [pscustomobject]@{
                name = [string]$_.Name
                enabled = [bool]$_.Enabled
                default_inbound_action = [string]$_.DefaultInboundAction
                block_all_inbound_traffic = [bool]$_.BlockAllInboundTraffic
              }
            }
        )

        $rule_rows = @(
          $rules | ForEach-Object {
            [pscustomobject]@{
              id = [string]$_.Name
              display_name = [string]$_.DisplayName
              action = [string]$_.Action
              profile = [string]$_.Profile
              edge_traversal_policy = [string]$_.EdgeTraversalPolicy
              enforcement_status = (@($_.EnforcementStatus) -join ',')
              owner = [string]$_.Owner
              local_only_mapping = [string]$_.LocalOnlyMapping
              loose_source_mapping = [string]$_.LooseSourceMapping
            }
          }
        )

        $port_rows = @(
          $rules | Get-NetFirewallPortFilter -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
              id = [string]$_.InstanceID
              protocol = [string]$_.Protocol
              local_port = (@($_.LocalPort) -join ',')
              remote_port = (@($_.RemotePort) -join ',')
              dynamic_target = [string]$_.DynamicTarget
              dynamic_transport = [string]$_.DynamicTransport
            }
          }
        )

        $address_rows = @(
          $rules | Get-NetFirewallAddressFilter -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
              id = [string]$_.InstanceID
              local_address = (@($_.LocalAddress) -join ',')
              remote_address = (@($_.RemoteAddress) -join ',')
            }
          }
        )

        $application_rows = @(
          $rules | Get-NetFirewallApplicationFilter -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
              id = [string]$_.InstanceID
              program = [string]$_.Program
              package = [string]$_.Package
            }
          }
        )

        $service_rows = @(
          $rules | Get-NetFirewallServiceFilter -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
              id = [string]$_.InstanceID
              service = [string]$_.Service
            }
          }
        )

        $interface_rows = @(
          $rules | Get-NetFirewallInterfaceFilter -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
              id = [string]$_.InstanceID
              interface_alias = (@($_.InterfaceAlias) -join ',')
            }
          }
        )

        $interface_type_rows = @(
          $rules | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
              id = [string]$_.InstanceID
              interface_type = [string]$_.InterfaceType
            }
          }
        )

        $security_rows = @(
          $rules | Get-NetFirewallSecurityFilter -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
              id = [string]$_.InstanceID
              authentication = [string]$_.Authentication
              encryption = [string]$_.Encryption
              override_block_rules = [bool]$_.OverrideBlockRules
              local_user = [string]$_.LocalUser
              remote_user = [string]$_.RemoteUser
              remote_machine = [string]$_.RemoteMachine
            }
          }
        )

        [pscustomobject]@{
          profiles = $profiles
          rules = $rule_rows
          ports = $port_rows
          addresses = $address_rows
          applications = $application_rows
          services = $service_rows
          interfaces = $interface_rows
          interface_types = $interface_type_rows
          security = $security_rows
        } | ConvertTo-Json -Depth 6 -Compress
        """;

    public async Task<FirewallCollection> CollectAsync(CancellationToken cancellationToken)
    {
        var observedAt = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();

        if (!OperatingSystem.IsWindows())
        {
            stopwatch.Stop();
            var diagnostic = new CollectorDiagnostic(
                "windows_firewall",
                CollectorStatus.Unavailable,
                "platform_unsupported",
                "Windows Firewall collection is only available on Windows.");
            return new(null, new("windows_firewall", CollectorStatus.Unavailable, observedAt, stopwatch.ElapsedMilliseconds, [diagnostic]));
        }

        var result = await PowerShellJsonRunner.RunAsync(
            FirewallScript,
            TimeSpan.FromSeconds(30),
            cancellationToken,
            TrustedWindowsPowerShellModule.NetSecurity);
        stopwatch.Stop();

        if (!result.Succeeded)
        {
            var diagnostic = new CollectorDiagnostic(
                "windows_firewall",
                CollectorStatus.Unavailable,
                result.TimedOut ? "firewall_timeout" : "firewall_unavailable",
                string.IsNullOrWhiteSpace(result.StandardError)
                    ? "The effective Windows Firewall policy could not be collected."
                    : result.StandardError);
            return new(null, new("windows_firewall", CollectorStatus.Unavailable, observedAt, stopwatch.ElapsedMilliseconds, [diagnostic]));
        }

        try
        {
            var document = JsonSerializer.Deserialize<FirewallDocument>(result.StandardOutput, JsonOptions)
                ?? throw new JsonException("Firewall output was empty.");
            var policy = WindowsFirewallPolicy.FromDocument(document);
            return new(policy, new("windows_firewall", CollectorStatus.Complete, observedAt, stopwatch.ElapsedMilliseconds, []));
        }
        catch (JsonException exception)
        {
            var diagnostic = new CollectorDiagnostic(
                "windows_firewall",
                CollectorStatus.Failed,
                "firewall_json_invalid",
                exception.Message);
            return new(null, new("windows_firewall", CollectorStatus.Failed, observedAt, stopwatch.ElapsedMilliseconds, [diagnostic]));
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
    };

    internal sealed record FirewallDocument(
        FirewallProfileRow[] Profiles,
        FirewallRuleRow[] Rules,
        PortFilterRow[] Ports,
        AddressFilterRow[] Addresses,
        ApplicationFilterRow[] Applications,
        ServiceFilterRow[] Services,
        InterfaceFilterRow[] Interfaces,
        InterfaceTypeFilterRow[] InterfaceTypes,
        SecurityFilterRow[] Security);

    internal sealed record FirewallProfileRow(
        string Name,
        bool Enabled,
        string DefaultInboundAction,
        bool BlockAllInboundTraffic);

    internal sealed record FirewallRuleRow(
        string Id,
        string DisplayName,
        string Action,
        string Profile,
        string EdgeTraversalPolicy,
        string EnforcementStatus,
        string Owner,
        string LocalOnlyMapping,
        string LooseSourceMapping);

    internal sealed record PortFilterRow(
        string Id,
        string Protocol,
        string LocalPort,
        string RemotePort,
        string DynamicTarget,
        string DynamicTransport);
    internal sealed record AddressFilterRow(string Id, string LocalAddress, string RemoteAddress);
    internal sealed record ApplicationFilterRow(string Id, string Program, string Package);
    internal sealed record ServiceFilterRow(string Id, string Service);
    internal sealed record InterfaceFilterRow(string Id, string InterfaceAlias);
    internal sealed record InterfaceTypeFilterRow(string Id, string InterfaceType);
    internal sealed record SecurityFilterRow(
        string Id,
        string Authentication,
        string Encryption,
        bool OverrideBlockRules,
        string LocalUser,
        string RemoteUser,
        string RemoteMachine);
}

public sealed class WindowsFirewallPolicy
{
    private readonly IReadOnlyList<FirewallProfile> profiles;
    private readonly IReadOnlyList<FirewallRule> rules;

    private WindowsFirewallPolicy(
        IReadOnlyList<FirewallProfile> profiles,
        IReadOnlyList<FirewallRule> rules)
    {
        this.profiles = profiles;
        this.rules = rules;
    }

    internal static WindowsFirewallPolicy FromDocument(WindowsFirewallCollector.FirewallDocument document)
    {
        static Dictionary<string, T> Index<T>(IEnumerable<T> items, Func<T, string> keySelector) =>
            items.GroupBy(keySelector, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(static group => group.Key, static group => group.First(), StringComparer.OrdinalIgnoreCase);

        var ports = Index(document.Ports, static item => item.Id);
        var addresses = Index(document.Addresses, static item => item.Id);
        var applications = Index(document.Applications, static item => item.Id);
        var services = Index(document.Services, static item => item.Id);
        var interfaces = Index(document.Interfaces, static item => item.Id);
        var interfaceTypes = Index(document.InterfaceTypes, static item => item.Id);
        var security = Index(document.Security, static item => item.Id);

        var profileRows = document.Profiles
            .Select(static row => new FirewallProfile(row.Name, row.Enabled, row.DefaultInboundAction, row.BlockAllInboundTraffic))
            .ToArray();
        var ruleRows = document.Rules.Select(row => new FirewallRule(
            row.Id,
            row.DisplayName,
            row.Action,
            Split(row.Profile),
            row.EdgeTraversalPolicy,
            row.EnforcementStatus,
            row.Owner,
            row.LocalOnlyMapping,
            row.LooseSourceMapping,
            ports.GetValueOrDefault(row.Id)?.Protocol ?? "Any",
            ports.GetValueOrDefault(row.Id)?.LocalPort ?? "Any",
            ports.GetValueOrDefault(row.Id)?.RemotePort ?? "Any",
            ports.GetValueOrDefault(row.Id)?.DynamicTarget ?? string.Empty,
            ports.GetValueOrDefault(row.Id)?.DynamicTransport ?? string.Empty,
            addresses.GetValueOrDefault(row.Id)?.LocalAddress ?? "Any",
            addresses.GetValueOrDefault(row.Id)?.RemoteAddress ?? "Any",
            applications.GetValueOrDefault(row.Id)?.Program ?? "Any",
            applications.GetValueOrDefault(row.Id)?.Package ?? string.Empty,
            services.GetValueOrDefault(row.Id)?.Service ?? "Any",
            interfaces.GetValueOrDefault(row.Id)?.InterfaceAlias ?? "Any",
            interfaceTypes.GetValueOrDefault(row.Id)?.InterfaceType ?? "Any",
            security.GetValueOrDefault(row.Id)?.Authentication ?? "NotRequired",
            security.GetValueOrDefault(row.Id)?.Encryption ?? "NotRequired",
            security.GetValueOrDefault(row.Id)?.OverrideBlockRules ?? false,
            security.GetValueOrDefault(row.Id)?.LocalUser ?? string.Empty,
            security.GetValueOrDefault(row.Id)?.RemoteUser ?? string.Empty,
            security.GetValueOrDefault(row.Id)?.RemoteMachine ?? string.Empty)).ToArray();

        return new(profileRows, ruleRows);
    }

    public HostPolicyEvidence Assess(ListenerEvidence listener)
    {
        if (listener.BindScope == BindScope.Loopback)
        {
            return new(
                FirewallVerdict.NotEvaluated,
                Confidence.High,
                "Loopback binding is host-local; remote-path policy is not applicable.",
                [],
                ["Host-local filtering behavior is outside this assessment."]);
        }

        var nonLoopbackInterfaces = listener.ActiveOn
            .Where(static item => !IsLoopbackAddress(item.Address))
            .ToArray();
        var hasUnknownActivePath = nonLoopbackInterfaces.Any(static item =>
        {
            var mappedProfiles = Split(item.Profile);
            return mappedProfiles.Length == 0
                || mappedProfiles.Any(static profile => profile.Equals("Unknown", StringComparison.OrdinalIgnoreCase));
        });
        var targets = nonLoopbackInterfaces
            .SelectMany(item => Split(item.Profile)
                .Where(static profile => !profile.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                .Select(profile => new PolicyTarget(item, profile)))
            .ToArray();
        if (targets.Length == 0)
        {
            return Unknown("No active Windows network profile could be mapped to this bind.");
        }

        var outcomes = targets
            .Select(target => new PolicyOutcome(target, AssessForTarget(listener, target)))
            .ToArray();
        var verdicts = outcomes.Select(static item => item.Evidence.Verdict).Distinct().ToArray();
        var verdict = verdicts.Length == 1 ? verdicts[0] : FirewallVerdict.Mixed;
        var confidence = outcomes.Any(static item => item.Evidence.Confidence == Confidence.Low)
            ? Confidence.Low
            : outcomes.Any(static item => item.Evidence.Confidence == Confidence.Medium)
                ? Confidence.Medium
                : Confidence.High;
        if (hasUnknownActivePath)
        {
            verdict = verdict == FirewallVerdict.Unknown ? FirewallVerdict.Unknown : FirewallVerdict.Mixed;
            confidence = Confidence.Low;
        }
        var summary = outcomes.Length == 1
            ? $"{outcomes[0].Target.Interface.Name} ({outcomes[0].Target.Profile}): {outcomes[0].Evidence.Summary}"
            : "Per-interface static policy: " + string.Join(
                "; ",
                outcomes.Select(static item =>
                    $"{item.Target.Interface.Name}/{item.Target.Profile}={item.Evidence.Verdict.ToString().ToLowerInvariant()}"));
        var matchingRules = outcomes.SelectMany(static item => item.Evidence.MatchingRules)
            .DistinctBy(static rule => rule.Id, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var limitations = outcomes.SelectMany(static item => item.Evidence.Limitations)
            .Concat(hasUnknownActivePath
                ? ["At least one active interface had no mapped Windows network profile and remains unknown."]
                : [])
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return new(verdict, confidence, summary, matchingRules, limitations);
    }

    private HostPolicyEvidence AssessForTarget(ListenerEvidence listener, PolicyTarget target)
    {
        var activeProfileNames = new[] { target.Profile };
        listener = listener with { ActiveOn = [target.Interface] };

        var relevantProfiles = profiles
            .Where(profile => activeProfileNames.Contains(profile.Name, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        if (relevantProfiles.Length == 0)
        {
            return Unknown($"No effective firewall profile matched: {string.Join(", ", activeProfileNames)}.");
        }

        if (relevantProfiles.All(static profile => !profile.Enabled))
        {
            return new(
                FirewallVerdict.Disabled,
                Confidence.Medium,
                "Windows Firewall is disabled for every mapped active profile.",
                [],
                ExternalLimitations());
        }

        if (relevantProfiles.Any(static profile => profile.Enabled && profile.BlockAllInboundTraffic))
        {
            return new(
                FirewallVerdict.Block,
                Confidence.Medium,
                "At least one mapped active profile has BlockAllInboundTraffic enabled.",
                [],
                ExternalLimitations());
        }

        var candidates = new List<MatchedRule>();
        var unresolvedRules = new List<MatchedRule>();
        foreach (var rule in rules)
        {
            var match = MatchRule(rule, listener, activeProfileNames);
            if (match.IsMatch)
            {
                candidates.Add(new(rule, match.Limitations));
            }
            else if (match.IsIndeterminate)
            {
                unresolvedRules.Add(new(rule, match.Limitations));
            }
        }

        var blocks = candidates.Where(static item => item.Rule.Action.Equals("Block", StringComparison.OrdinalIgnoreCase)).ToArray();
        var allows = candidates.Where(static item => item.Rule.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase)).ToArray();
        var matched = candidates.Select(ToEvidence).ToArray();
        var unresolvedLimitations = unresolvedRules.SelectMany(static item => item.Limitations).ToArray();
        var limitations = candidates.SelectMany(static item => item.Limitations)
            .Concat(SummarizeUnresolved(unresolvedLimitations))
            .Concat(ExternalLimitations())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var constrained = candidates.Any(static item => item.Limitations.Count > 0)
            || unresolvedLimitations.Length > 0;
        var hasUnresolvedAllow = unresolvedRules.Any(static item => item.Rule.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase));
        var hasUnresolvedBlock = unresolvedRules.Any(static item => item.Rule.Action.Equals("Block", StringComparison.OrdinalIgnoreCase));
        var hasUnresolvedBypassAllow = unresolvedRules.Any(static item =>
            item.Rule.OverrideBlockRules
            && item.Rule.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase));

        if (blocks.Length > 0)
        {
            if (hasUnresolvedBypassAllow)
            {
                return new(
                    FirewallVerdict.Mixed,
                    Confidence.Low,
                    "A matching block rule was observed, but a potentially applicable authenticated-bypass allow could not be resolved.",
                    matched,
                    limitations);
            }

            return new(
                FirewallVerdict.Block,
                constrained ? Confidence.Low : Confidence.Medium,
                allows.Length > 0
                    ? "A matching explicit block rule takes precedence over matching allow rules."
                    : "A matching explicit inbound block rule was observed.",
                matched,
                limitations);
        }

        if (allows.Length > 0)
        {
            if (hasUnresolvedBlock)
            {
                return new(
                    FirewallVerdict.Mixed,
                    Confidence.Low,
                    "A matching allow rule was observed, but a potentially applicable block rule could not be resolved.",
                    matched,
                    limitations);
            }

            return new(
                constrained ? FirewallVerdict.Mixed : FirewallVerdict.Allow,
                constrained ? Confidence.Low : Confidence.Medium,
                constrained
                    ? "An inbound allow rule may apply, but it has source, interface, security, or unsupported constraints."
                    : "A matching explicit inbound allow rule was observed; static host policy indicates allow.",
                matched,
                limitations);
        }

        var enabledProfiles = relevantProfiles.Where(static profile => profile.Enabled).ToArray();
        var defaultActions = enabledProfiles
            .Select(static profile => profile.DefaultInboundAction)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (defaultActions.Length == 1 && defaultActions[0].Equals("Block", StringComparison.OrdinalIgnoreCase))
        {
            if (hasUnresolvedAllow)
            {
                return new(
                    FirewallVerdict.Mixed,
                    Confidence.Low,
                    "The active profiles default to block, but a potentially applicable allow rule has unresolved constraints.",
                    [],
                    limitations);
            }

            return new(
                FirewallVerdict.Block,
                Confidence.Medium,
                "No matching allow rule was observed; the mapped active profiles default to blocking inbound traffic.",
                [],
                ExternalLimitations());
        }

        if (defaultActions.Length == 1 && defaultActions[0].Equals("Allow", StringComparison.OrdinalIgnoreCase))
        {
            if (hasUnresolvedBlock)
            {
                return new(
                    FirewallVerdict.Mixed,
                    Confidence.Low,
                    "The active profiles default to allow, but a potentially applicable block rule has unresolved constraints.",
                    [],
                    limitations);
            }

            return new(
                FirewallVerdict.Allow,
                Confidence.Medium,
                "No matching block rule was observed; the mapped active profiles default to allowing inbound traffic.",
                [],
                ExternalLimitations());
        }

        return new(
            FirewallVerdict.Mixed,
            Confidence.Low,
            "Mapped active profiles have different or unresolved default inbound actions.",
            [],
            ExternalLimitations());
    }

    private static bool IsLoopbackAddress(string value) =>
        IPAddress.TryParse(value, out var address) && IPAddress.IsLoopback(address);

    private static RuleMatch MatchRule(
        FirewallRule rule,
        ListenerEvidence listener,
        IReadOnlyList<string> activeProfiles)
    {
        var limitations = new List<string>();

        if (!ProfilesMatch(rule.Profiles, activeProfiles)
            || !ProtocolMatches(rule.Protocol, listener.Protocol))
        {
            return RuleMatch.No;
        }

        var indeterminate = false;

        var programMatch = ProgramMatches(rule.Program, listener.Owner);
        if (programMatch == MatchResult.No)
        {
            return RuleMatch.No;
        }

        if (programMatch == MatchResult.Unknown)
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' may target this executable, but its full path was unavailable.");
        }

        var serviceMatch = ServiceMatches(rule.Service, listener.Owner);
        if (serviceMatch == MatchResult.No)
        {
            return RuleMatch.No;
        }

        if (serviceMatch == MatchResult.Unknown)
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' has a service constraint that could not be attributed.");
        }

        var interfaceMatch = InterfaceMatches(rule.InterfaceAlias, listener.ActiveOn);
        if (interfaceMatch == MatchResult.No)
        {
            return RuleMatch.No;
        }

        if (interfaceMatch == MatchResult.Unknown)
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' has an interface constraint that could not be mapped.");
        }

        var portMatch = PortMatches(rule.LocalPort, listener.LocalPort);
        if (portMatch == MatchResult.No)
        {
            return RuleMatch.No;
        }

        if (portMatch == MatchResult.Unknown)
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' uses an unsupported local-port token: {rule.LocalPort}.");
        }

        var concreteAddress = listener.LocalAddress is "0.0.0.0" or "::"
            && listener.ActiveOn.Count == 1
            ? listener.ActiveOn[0].Address
            : listener.LocalAddress;
        var addressMatch = AddressMatches(rule.LocalAddress, concreteAddress);
        if (addressMatch == MatchResult.No)
        {
            return RuleMatch.No;
        }

        if (addressMatch == MatchResult.Unknown)
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' uses a conditional or unsupported local-address expression: {rule.LocalAddress}.");
        }

        if (!IsAny(rule.RemoteAddress))
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' applies only to remote address set '{rule.RemoteAddress}'; no source address was supplied.");
        }

        if (!IsAnyOrEmpty(rule.RemotePort))
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' is limited to remote port set '{rule.RemotePort}'.");
        }

        if (!IsAnyOrEmpty(rule.DynamicTarget) || !IsAnyOrEmpty(rule.DynamicTransport))
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' uses a dynamic target or transport constraint.");
        }

        if (!IsAny(rule.InterfaceType))
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' is limited to interface type '{rule.InterfaceType}'.");
        }

        if (!string.IsNullOrWhiteSpace(rule.Package))
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' includes a packaged-app constraint that was not fully evaluated.");
        }

        if (!rule.Authentication.Equals("NotRequired", StringComparison.OrdinalIgnoreCase)
            && !rule.Authentication.Equals("Any", StringComparison.OrdinalIgnoreCase))
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' requires authentication/IPsec: {rule.Authentication}.");
        }

        if (!rule.Encryption.Equals("NotRequired", StringComparison.OrdinalIgnoreCase)
            && !rule.Encryption.Equals("Any", StringComparison.OrdinalIgnoreCase))
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' requires encryption/IPsec: {rule.Encryption}.");
        }

        if (rule.OverrideBlockRules)
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' uses authenticated bypass semantics.");
        }

        if (!IsAnyOrEmpty(rule.LocalUser)
            || !IsAnyOrEmpty(rule.RemoteUser)
            || !IsAnyOrEmpty(rule.RemoteMachine))
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' contains user or machine authorization constraints.");
        }

        if (!IsAnyOrEmpty(rule.Owner))
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' has an owner constraint.");
        }

        if (!IsFalseLike(rule.LocalOnlyMapping) || !IsFalseLike(rule.LooseSourceMapping))
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' uses local-only or loose-source mapping semantics.");
        }

        if (!IsFullyEnforced(rule.EnforcementStatus))
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' was not reported as fully enforced: {rule.EnforcementStatus}.");
        }

        if (!rule.EdgeTraversalPolicy.Equals("Block", StringComparison.OrdinalIgnoreCase)
            && !rule.EdgeTraversalPolicy.Equals("DeferToUser", StringComparison.OrdinalIgnoreCase))
        {
            indeterminate = true;
            limitations.Add($"Rule '{rule.DisplayName}' has edge-traversal policy '{rule.EdgeTraversalPolicy}'.");
        }

        return indeterminate
            ? new(false, true, limitations)
            : new(true, false, limitations);
    }

    private static bool ProfilesMatch(IReadOnlyList<string> ruleProfiles, IReadOnlyList<string> activeProfiles) =>
        ruleProfiles.Count == 0
        || ruleProfiles.Any(IsAny)
        || ruleProfiles.Any(profile => activeProfiles.Contains(profile, StringComparer.OrdinalIgnoreCase));

    private static bool ProtocolMatches(string protocol, TransportProtocol listenerProtocol) =>
        IsAny(protocol)
        || (listenerProtocol == TransportProtocol.Tcp && (protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) || protocol == "6"))
        || (listenerProtocol == TransportProtocol.Udp && (protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) || protocol == "17"));

    private static MatchResult ProgramMatches(string program, OwnerEvidence owner)
    {
        if (IsAny(program) || string.IsNullOrWhiteSpace(program))
        {
            return MatchResult.Yes;
        }

        var expanded = Environment.ExpandEnvironmentVariables(program);
        if (!string.IsNullOrWhiteSpace(owner.ImagePath))
        {
            return string.Equals(expanded, owner.ImagePath, StringComparison.OrdinalIgnoreCase)
                ? MatchResult.Yes
                : MatchResult.No;
        }

        return Path.GetFileName(expanded).Equals(owner.ImageName, StringComparison.OrdinalIgnoreCase)
            ? MatchResult.Unknown
            : MatchResult.No;
    }

    private static MatchResult ServiceMatches(string service, OwnerEvidence owner)
    {
        if (IsAny(service) || string.IsNullOrWhiteSpace(service))
        {
            return MatchResult.Yes;
        }

        if (owner.Services.Count == 0)
        {
            return MatchResult.Unknown;
        }

        if (!owner.Services.Contains(service, StringComparer.OrdinalIgnoreCase))
        {
            return MatchResult.No;
        }

        return owner.ServicesAreCandidates ? MatchResult.Unknown : MatchResult.Yes;
    }

    private static MatchResult InterfaceMatches(string aliases, IReadOnlyList<NetworkInterfaceEvidence> activeOn)
    {
        if (IsAny(aliases) || string.IsNullOrWhiteSpace(aliases))
        {
            return MatchResult.Yes;
        }

        if (activeOn.Count == 0)
        {
            return MatchResult.Unknown;
        }

        return Split(aliases).Any(alias => activeOn.Any(item => item.Name.Equals(alias, StringComparison.OrdinalIgnoreCase)))
            ? MatchResult.Yes
            : MatchResult.No;
    }

    private static MatchResult PortMatches(string expression, int port)
    {
        if (IsAny(expression) || string.IsNullOrWhiteSpace(expression))
        {
            return MatchResult.Yes;
        }

        var unknown = false;
        foreach (var token in Split(expression))
        {
            if (int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out var exact))
            {
                if (exact == port)
                {
                    return MatchResult.Yes;
                }

                continue;
            }

            var range = token.Split('-', 2, StringSplitOptions.TrimEntries);
            if (range.Length == 2
                && int.TryParse(range[0], NumberStyles.None, CultureInfo.InvariantCulture, out var start)
                && int.TryParse(range[1], NumberStyles.None, CultureInfo.InvariantCulture, out var end))
            {
                if (port >= start && port <= end)
                {
                    return MatchResult.Yes;
                }

                continue;
            }

            unknown = true;
        }

        return unknown ? MatchResult.Unknown : MatchResult.No;
    }

    private static MatchResult AddressMatches(string expression, string listenerAddress)
    {
        if (IsAny(expression) || string.IsNullOrWhiteSpace(expression))
        {
            return MatchResult.Yes;
        }

        if (!IPAddress.TryParse(listenerAddress, out var address))
        {
            return MatchResult.Unknown;
        }

        var unknown = false;
        foreach (var token in Split(expression))
        {
            if (IPAddress.TryParse(token, out var exact))
            {
                if (exact.Equals(address))
                {
                    return MatchResult.Yes;
                }

                continue;
            }

            if (token.Contains('/', StringComparison.Ordinal) || token.Equals("LocalSubnet", StringComparison.OrdinalIgnoreCase))
            {
                unknown = true;
                continue;
            }

            unknown = true;
        }

        return unknown ? MatchResult.Unknown : MatchResult.No;
    }

    private static FirewallRuleEvidence ToEvidence(MatchedRule match) => new(
        match.Rule.Id,
        match.Rule.DisplayName,
        match.Rule.Action,
        match.Rule.Profiles,
        match.Rule.Protocol,
        match.Rule.LocalPort,
        match.Rule.LocalAddress,
        match.Rule.RemoteAddress,
        match.Rule.Program,
        match.Rule.Service,
        match.Limitations);

    private static HostPolicyEvidence Unknown(string summary) => new(
        FirewallVerdict.Unknown,
        Confidence.Low,
        summary,
        [],
        ExternalLimitations());

    private static string[] ExternalLimitations() =>
    [
        "This is static Windows Firewall evidence, not a packet-classification oracle.",
        "Third-party WFP filters, IPsec negotiation, router/NAT policy, cloud controls, and the remote path were not tested.",
    ];

    private static IEnumerable<string> SummarizeUnresolved(IReadOnlyCollection<string> unresolved)
    {
        if (unresolved.Count > 0)
        {
            yield return $"{unresolved.Count} firewall rule condition(s) could not be fully evaluated; they were not treated as matches.";
        }
    }

    private static bool IsAny(string value) =>
        value.Equals("Any", StringComparison.OrdinalIgnoreCase)
        || value.Equals("*", StringComparison.OrdinalIgnoreCase);

    private static bool IsAnyOrEmpty(string value) => string.IsNullOrWhiteSpace(value) || IsAny(value);

    private static bool IsFalseLike(string value) =>
        string.IsNullOrWhiteSpace(value)
        || value.Equals("False", StringComparison.OrdinalIgnoreCase)
        || value.Equals("NotConfigured", StringComparison.OrdinalIgnoreCase);

    private static bool IsFullyEnforced(string value) =>
        value.Equals("Full", StringComparison.OrdinalIgnoreCase)
        || Split(value).Any(static token => token.Equals("Enforced", StringComparison.OrdinalIgnoreCase));

    private static string[] Split(string value) =>
        value.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private enum MatchResult
    {
        No,
        Yes,
        Unknown,
    }

    private sealed record RuleMatch(bool IsMatch, bool IsIndeterminate, IReadOnlyList<string> Limitations)
    {
        public static RuleMatch No { get; } = new(false, false, []);
    }

    private sealed record MatchedRule(FirewallRule Rule, IReadOnlyList<string> Limitations);

    private sealed record PolicyTarget(NetworkInterfaceEvidence Interface, string Profile);

    private sealed record PolicyOutcome(PolicyTarget Target, HostPolicyEvidence Evidence);

    private sealed record FirewallProfile(
        string Name,
        bool Enabled,
        string DefaultInboundAction,
        bool BlockAllInboundTraffic);

    private sealed record FirewallRule(
        string Id,
        string DisplayName,
        string Action,
        IReadOnlyList<string> Profiles,
        string EdgeTraversalPolicy,
        string EnforcementStatus,
        string Owner,
        string LocalOnlyMapping,
        string LooseSourceMapping,
        string Protocol,
        string LocalPort,
        string RemotePort,
        string DynamicTarget,
        string DynamicTransport,
        string LocalAddress,
        string RemoteAddress,
        string Program,
        string Package,
        string Service,
        string InterfaceAlias,
        string InterfaceType,
        string Authentication,
        string Encryption,
        bool OverrideBlockRules,
        string LocalUser,
        string RemoteUser,
        string RemoteMachine);
}
