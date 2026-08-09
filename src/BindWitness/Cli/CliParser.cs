using System.Globalization;
using BindWitness.Domain;

namespace BindWitness.Cli;

public static class CliParser
{
    public static CliOptions Parse(IReadOnlyList<string> arguments)
    {
        if (arguments.Count == 0)
        {
            return new(CommandKind.List);
        }

        var command = CommandKind.List;
        int? port = null;
        TransportProtocol? protocol = null;
        string? process = null;
        string? scope = null;
        string? input = null;
        string? output = null;
        var json = false;
        var firewall = false;
        var firewallExplicitlyDisabled = false;
        var evidence = false;
        var strict = false;
        var force = false;
        var allowIncomplete = false;
        var includeUdp = false;
        var includePrivate = false;
        var resolveAccounts = false;
        TimeSpan? interval = null;
        int? iterations = null;
        var index = 0;

        if (!arguments[0].StartsWith("-", StringComparison.Ordinal))
        {
            var first = arguments[0];
            if (TryParseQuery(first, out var queryProtocol, out var queryPort))
            {
                command = CommandKind.Inspect;
                protocol = queryProtocol;
                port = queryPort;
                index++;
            }
            else
            {
                command = first.ToLowerInvariant() switch
                {
                    "list" or "ls" => CommandKind.List,
                    "inspect" or "explain" => CommandKind.Inspect,
                    "lock" => CommandKind.Lock,
                    "snapshot" => CommandKind.Snapshot,
                    "diff" => CommandKind.Diff,
                    "check" => CommandKind.Check,
                    "watch" => CommandKind.Watch,
                    "doctor" => CommandKind.Doctor,
                    "help" => CommandKind.Help,
                    "version" => CommandKind.Version,
                    _ => throw new CliUsageException($"Unknown command or port query '{first}'."),
                };
                index++;
            }
        }

        var positionals = new List<string>();
        while (index < arguments.Count)
        {
            var argument = arguments[index++];
            switch (argument)
            {
                case "-h" or "--help":
                    command = CommandKind.Help;
                    break;
                case "--version":
                    command = CommandKind.Version;
                    break;
                case "--json":
                    json = true;
                    break;
                case "--format":
                    {
                        var format = RequireValue(arguments, ref index, argument);
                        json = format.Equals("json", StringComparison.OrdinalIgnoreCase)
                            || format.Equals("jsonl", StringComparison.OrdinalIgnoreCase);
                        if (!json && !format.Equals("table", StringComparison.OrdinalIgnoreCase)
                            && !format.Equals("text", StringComparison.OrdinalIgnoreCase))
                        {
                            throw new CliUsageException("--format must be table, text, json, or jsonl.");
                        }

                        break;
                    }
                case "--firewall":
                    firewall = true;
                    break;
                case "--no-firewall":
                    firewallExplicitlyDisabled = true;
                    firewall = false;
                    break;
                case "--evidence":
                    evidence = true;
                    firewall = true;
                    break;
                case "--strict" or "--require-complete":
                    strict = true;
                    break;
                case "--force":
                    force = true;
                    break;
                case "--allow-incomplete":
                    allowIncomplete = true;
                    break;
                case "--include-udp":
                    includeUdp = true;
                    break;
                case "--include-private":
                    includePrivate = true;
                    break;
                case "--resolve-accounts":
                    resolveAccounts = true;
                    break;
                case "-p" or "--port":
                    port = ParsePort(RequireValue(arguments, ref index, argument));
                    break;
                case "--proto" or "--protocol":
                    protocol = ParseProtocol(RequireValue(arguments, ref index, argument));
                    break;
                case "--process":
                    process = RequireValue(arguments, ref index, argument);
                    break;
                case "--scope":
                    scope = ParseScope(RequireValue(arguments, ref index, argument));
                    break;
                case "-o" or "--output":
                    output = RequireValue(arguments, ref index, argument);
                    break;
                case "--interval":
                    interval = ParseDuration(RequireValue(arguments, ref index, argument));
                    break;
                case "--iterations":
                    iterations = ParsePositiveInt(RequireValue(arguments, ref index, argument), argument);
                    break;
                default:
                    if (argument.StartsWith("-", StringComparison.Ordinal))
                    {
                        throw new CliUsageException($"Unknown option '{argument}'.");
                    }

                    positionals.Add(argument);
                    break;
            }
        }

        if (command == CommandKind.Inspect && port is null && positionals.Count > 0)
        {
            if (!TryParseQuery(positionals[0], out var queryProtocol, out var queryPort))
            {
                throw new CliUsageException($"'{positionals[0]}' is not a valid port query.");
            }

            protocol = queryProtocol ?? protocol;
            port = queryPort;
            positionals.RemoveAt(0);
        }

        if (command is CommandKind.Diff or CommandKind.Check)
        {
            if (positionals.Count == 0)
            {
                throw new CliUsageException($"{command.ToString().ToLowerInvariant()} requires a lockfile path.");
            }

            input = positionals[0];
            positionals.RemoveAt(0);

            if (port is not null || protocol is not null || process is not null || scope is not null)
            {
                throw new CliUsageException("diff/check use the selector stored in the lockfile; filter options are not accepted.");
            }
        }

        if (positionals.Count > 0)
        {
            throw new CliUsageException($"Unexpected argument '{positionals[0]}'.");
        }

        if (command == CommandKind.Inspect && port is null)
        {
            throw new CliUsageException("inspect requires a port, for example: bindwitness tcp:8080");
        }

        if (command == CommandKind.Lock)
        {
            if (process is not null || scope is not null)
            {
                throw new CliUsageException("lock supports port/protocol selectors only; process and scope selectors can fail open when metadata degrades.");
            }

            output ??= "listeners.lock.json";
        }

        if (command == CommandKind.Inspect && !firewallExplicitlyDisabled)
        {
            firewall = true;
        }

        if (command == CommandKind.Doctor && !firewallExplicitlyDisabled)
        {
            firewall = true;
        }

        return new(
            command,
            port,
            protocol,
            process,
            scope,
            input,
            output,
            json,
            firewall,
            evidence,
            strict,
            force,
            allowIncomplete,
            includeUdp,
            includePrivate,
            resolveAccounts,
            interval,
            iterations);
    }

    private static string RequireValue(IReadOnlyList<string> arguments, ref int index, string option)
    {
        if (index >= arguments.Count)
        {
            throw new CliUsageException($"{option} requires a value.");
        }

        return arguments[index++];
    }

    private static bool TryParseQuery(string value, out TransportProtocol? protocol, out int port)
    {
        protocol = null;
        port = 0;
        var parts = value.Split(':', 2, StringSplitOptions.TrimEntries);
        if (parts.Length == 1)
        {
            return int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out port)
                && port is >= 1 and <= 65535;
        }

        try
        {
            protocol = ParseProtocol(parts[0]);
            port = ParsePort(parts[1]);
            return true;
        }
        catch (CliUsageException)
        {
            protocol = null;
            port = 0;
            return false;
        }
    }

    private static int ParsePort(string value)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            || port is < 1 or > 65535)
        {
            throw new CliUsageException($"Port '{value}' must be an integer from 1 to 65535.");
        }

        return port;
    }

    private static TransportProtocol ParseProtocol(string value) => value.ToLowerInvariant() switch
    {
        "tcp" => TransportProtocol.Tcp,
        "udp" => TransportProtocol.Udp,
        _ => throw new CliUsageException($"Protocol '{value}' must be tcp or udp."),
    };

    private static string ParseScope(string value) => value.ToLowerInvariant() switch
    {
        "loopback" => "loopback",
        "interface" => "interface",
        "wildcard" => "wildcard",
        "non-loopback" or "remote" => "non-loopback",
        _ => throw new CliUsageException("--scope must be loopback, interface, wildcard, or non-loopback."),
    };

    private static TimeSpan ParseDuration(string value)
    {
        var factor = value.EndsWith("ms", StringComparison.OrdinalIgnoreCase) ? 1d
            : value.EndsWith('s') ? 1000d
            : value.EndsWith('m') ? 60000d
            : 1000d;
        var number = value.EndsWith("ms", StringComparison.OrdinalIgnoreCase) ? value[..^2]
            : value.EndsWith('s') || value.EndsWith('m') ? value[..^1]
            : value;
        if (!double.TryParse(number, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var amount)
            || amount <= 0)
        {
            throw new CliUsageException($"Duration '{value}' is invalid. Examples: 500ms, 1s, 2m.");
        }

        var duration = TimeSpan.FromMilliseconds(amount * factor);
        if (duration < TimeSpan.FromMilliseconds(250))
        {
            throw new CliUsageException("Watch intervals below 250ms are not supported.");
        }

        return duration;
    }

    private static int ParsePositiveInt(string value, string option)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var result) || result <= 0)
        {
            throw new CliUsageException($"{option} requires a positive integer.");
        }

        return result;
    }
}
