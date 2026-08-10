using System.Globalization;
using System.Text.RegularExpressions;

namespace PortCVE.Remote;

internal sealed record RemoteFingerprintAnalysis(
    IReadOnlyList<RemoteFingerprint> Fingerprints,
    IReadOnlyList<RemoteProductCandidate> ProductCandidates);

internal static class RemoteFingerprintParser
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
    private static readonly Regex SshBanner = CreateRegex(
        @"^SSH-(?<protocol>1\.99|2\.0)-(?<software>[^\s]+)");
    private static readonly Regex HttpStatus = CreateRegex(
        @"^HTTP/(?<version>1\.[01])\s+(?<status>\d{3})(?:\s+(?<reason>.*))?$");
    private static readonly Regex HeaderName = CreateRegex(@"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$");
    private static readonly IReadOnlySet<string> NoProducts = new HashSet<string>(StringComparer.Ordinal);
    private static readonly IReadOnlySet<string> SshProducts = ProductSet(
        "OpenSSH", "Dropbear SSH", "libssh");
    private static readonly IReadOnlySet<string> FtpProducts = ProductSet(
        "ProFTPD", "vsftpd", "FileZilla Server");
    private static readonly IReadOnlySet<string> SmtpProducts = ProductSet(
        "Exim", "Sendmail");
    private static readonly IReadOnlySet<string> MailboxProducts = ProductSet(
        "Dovecot", "Courier");
    private static readonly IReadOnlySet<string> HttpProducts = ProductSet(
        "Apache HTTP Server", "nginx", "Microsoft IIS", "lighttpd", "OpenResty",
        "LiteSpeed", "Jetty", "Caddy", "gunicorn", "uvicorn", "Werkzeug", "Kestrel",
        "PHP", "ASP.NET");
    private static readonly ProductPattern[] ProductPatterns = [
        new("OpenSSH", CreateRegex(
            @"\AOpenSSH_(?<version>[0-9]+(?:\.[0-9]+)+p[0-9]+)\z")),
        // These catalog-eligible patterns are anchored to the product's
        // protocol field or canonical greeting. Do not loosen them into a
        // contains-search: greeting text is remotely controlled and a nearby
        // product name is not evidence that the named implementation spoke.
        new("Dropbear SSH", CreateRegex(@"\Adropbear_(?<version>[0-9]+(?:\.[0-9]+)+)\z")),
        new("libssh", CreateRegex(@"\blibssh[_/ -](?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("ProFTPD", CreateRegex(
            @"\A220 ProFTPD (?<version>[0-9]+(?:\.[0-9]+)+[a-z]?) Server \(.+\) \[[^\[\]]+\]\z")),
        new("vsftpd", CreateRegex(
            @"\A220 \(vsFTPd (?<version>[0-9]+(?:\.[0-9]+)+)\)\z")),
        new("FileZilla Server", CreateRegex(@"\bFileZilla Server(?:\s+|/)(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("Exim", CreateRegex(
            @"\A220 [^\s]+ ESMTP Exim (?<version>[0-9]+(?:\.[0-9]+)+)(?:\s+.+)?\z")),
        new("Sendmail", CreateRegex(@"\bSendmail(?:\s+|/)(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("Dovecot", CreateRegex(@"\bDovecot(?:\s+|/)(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("Courier", CreateRegex(@"\bCourier(?:\s+|/)(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("Apache HTTP Server", CreateRegex(@"\bApache(?:\s+HTTP(?:\s+Server)?)?/(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("nginx", CreateRegex(@"\bnginx/(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("Microsoft IIS", CreateRegex(@"\bMicrosoft-IIS/(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("lighttpd", CreateRegex(@"\blighttpd/(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("OpenResty", CreateRegex(@"\bopenresty/(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("LiteSpeed", CreateRegex(@"\bLiteSpeed(?:\s+|/)(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("Jetty", CreateRegex(@"\bJetty\((?<version>[0-9][0-9A-Za-z._+~-]*)\)")),
        new("Caddy", CreateRegex(@"\bCaddy(?:\s+|/)(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("gunicorn", CreateRegex(@"\bgunicorn/(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("uvicorn", CreateRegex(@"\buvicorn/(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("Werkzeug", CreateRegex(@"\bWerkzeug/(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("Kestrel", CreateRegex(@"\bKestrel/(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("PHP", CreateRegex(@"\bPHP/(?<version>[0-9][0-9A-Za-z._+~-]*)")),
        new("ASP.NET", CreateRegex(@"\bASP\.NET(?:\s+|/)(?<version>[0-9][0-9A-Za-z._+~-]*)")),
    ];

    public static RemoteFingerprintAnalysis AnalyzeGreeting(
        string greeting,
        int maximumEvidenceBytes,
        bool isComplete = true)
    {
        var evidence = RemoteEvidenceSanitizer.Sanitize(greeting, maximumEvidenceBytes);
        if (evidence.Length == 0)
        {
            return new([], []);
        }

        if (!isComplete)
        {
            return new(
                [CreateFingerprint(
                    RemoteFingerprintKind.Greeting,
                    "unknown",
                    RemoteFingerprintConfidence.Observed,
                    "passive-greeting",
                    evidence,
                    new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["complete"] = "false",
                    })],
                []);
        }

        var fingerprints = new List<RemoteFingerprint>();
        var candidates = new List<RemoteProductCandidate>();
        var ssh = SshBanner.Match(evidence);
        var ftp = LooksLikeFtp(evidence);
        var smtp = LooksLikeSmtp(evidence);
        IReadOnlySet<string> allowedProducts;
        if (ssh.Success)
        {
            fingerprints.Add(CreateFingerprint(
                RemoteFingerprintKind.Ssh,
                "ssh",
                RemoteFingerprintConfidence.ProtocolConfirmed,
                "passive-greeting",
                evidence,
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["protocolVersion"] = ssh.Groups["protocol"].Value,
                    ["software"] = ssh.Groups["software"].Value,
                }));
            allowedProducts = SshProducts;
        }
        else if (ftp && !smtp)
        {
            fingerprints.Add(CreateServiceFingerprint(RemoteFingerprintKind.Ftp, "ftp", evidence));
            allowedProducts = FtpProducts;
        }
        else if (smtp && !ftp)
        {
            fingerprints.Add(CreateServiceFingerprint(RemoteFingerprintKind.Smtp, "smtp", evidence));
            allowedProducts = SmtpProducts;
        }
        else if (LooksLikePop3(evidence))
        {
            fingerprints.Add(CreateServiceFingerprint(RemoteFingerprintKind.Pop3, "pop3", evidence));
            allowedProducts = MailboxProducts;
        }
        else if (LooksLikeImap(evidence))
        {
            fingerprints.Add(CreateServiceFingerprint(RemoteFingerprintKind.Imap, "imap", evidence));
            allowedProducts = MailboxProducts;
        }
        else
        {
            fingerprints.Add(CreateFingerprint(
                RemoteFingerprintKind.Greeting,
                "unknown",
                RemoteFingerprintConfidence.Observed,
                "passive-greeting",
                evidence));
            allowedProducts = NoProducts;
        }

        candidates.AddRange(ExtractProducts(
            ssh.Success ? ssh.Groups["software"].Value : evidence,
            "passive-greeting",
            RemoteProductConfidence.BannerPattern,
            allowedProducts));
        return new(fingerprints, DeduplicateCandidates(candidates));
    }

    public static RemoteFingerprintAnalysis AnalyzeHttpResponse(
        string headerBlock,
        RemoteFingerprintKind kind,
        string source,
        int maximumEvidenceBytes,
        bool headersComplete = true)
    {
        var lines = headerBlock
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Split('\n');
        if (lines.Length == 0)
        {
            return new([], []);
        }

        var statusLine = RemoteEvidenceSanitizer.Sanitize(lines[0], maximumEvidenceBytes);
        var status = HttpStatus.Match(statusLine);
        if (!status.Success)
        {
            return new([], []);
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in lines.Skip(1).Take(100))
        {
            if (rawLine.Length == 0)
            {
                break;
            }

            var separator = rawLine.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            var name = rawLine[..separator].Trim();
            if (!HeaderName.IsMatch(name))
            {
                continue;
            }

            var value = RemoteEvidenceSanitizer.Sanitize(rawLine[(separator + 1)..], maximumEvidenceBytes);
            if (value.Length > 0 && !headers.ContainsKey(name))
            {
                headers.Add(name, value);
            }
        }

        var attributes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["httpVersion"] = status.Groups["version"].Value,
            ["statusCode"] = status.Groups["status"].Value,
            ["headersComplete"] = headersComplete ? "true" : "false",
        };
        CopyHeader(headers, attributes, "Server", "server");
        CopyHeader(headers, attributes, "X-Powered-By", "xPoweredBy");
        CopyHeader(headers, attributes, "Allow", "allow");
        CopyHeader(headers, attributes, "Location", "location");

        var selectedEvidence = string.Join(
            " | ",
            new[]
            {
                statusLine,
                HeaderEvidence(headers, "Server"),
                HeaderEvidence(headers, "X-Powered-By"),
                HeaderEvidence(headers, "Allow"),
                HeaderEvidence(headers, "Location"),
            }.Where(static item => !string.IsNullOrEmpty(item)));
        selectedEvidence = RemoteEvidenceSanitizer.Sanitize(selectedEvidence, maximumEvidenceBytes);

        var candidates = new List<RemoteProductCandidate>();
        foreach (var headerName in new[] { "Server", "X-Powered-By" })
        {
            if (headers.TryGetValue(headerName, out var value))
            {
                candidates.AddRange(ExtractProducts(
                    value,
                    $"{source}:{headerName.ToLowerInvariant()}",
                    RemoteProductConfidence.HeaderReported,
                    HttpProducts));
            }
        }

        return new(
            [CreateFingerprint(
                kind,
                "http",
                RemoteFingerprintConfidence.ProtocolConfirmed,
                source,
                selectedEvidence,
                attributes)],
            DeduplicateCandidates(candidates));
    }

    private static RemoteFingerprint CreateServiceFingerprint(
        RemoteFingerprintKind kind,
        string service,
        string evidence) =>
        CreateFingerprint(
            kind,
            service,
            RemoteFingerprintConfidence.StrongPattern,
            "passive-greeting",
            evidence);

    private static RemoteFingerprint CreateFingerprint(
        RemoteFingerprintKind kind,
        string service,
        RemoteFingerprintConfidence confidence,
        string source,
        string evidence,
        IDictionary<string, string>? attributes = null) =>
        new(
            kind,
            service,
            confidence,
            source,
            evidence,
            RemoteFingerprint.ReadOnlyAttributes(attributes));

    private static IEnumerable<RemoteProductCandidate> ExtractProducts(
        string evidence,
        string source,
        RemoteProductConfidence confidence,
        IReadOnlySet<string> allowedProducts)
    {
        foreach (var pattern in ProductPatterns)
        {
            if (!allowedProducts.Contains(pattern.Product))
            {
                continue;
            }

            var match = pattern.Pattern.Match(evidence);
            if (!match.Success)
            {
                continue;
            }

            var version = match.Groups["version"].Success
                ? match.Groups["version"].Value
                : null;
            yield return new(
                pattern.Product,
                version,
                confidence,
                source,
                match.Value);
        }
    }

    private static IReadOnlyList<RemoteProductCandidate> DeduplicateCandidates(
        IEnumerable<RemoteProductCandidate> candidates) =>
        candidates
            .DistinctBy(static candidate => (
                candidate.Product.ToUpperInvariant(),
                candidate.Version?.ToUpperInvariant(),
                candidate.Source.ToUpperInvariant()))
            .ToArray();

    private static bool LooksLikeFtp(string evidence) =>
        evidence.StartsWith("220", StringComparison.Ordinal)
        && ContainsAny(evidence, " FTP", "FTP server", "ProFTPD", "vsFTPd", "FileZilla Server");

    private static bool LooksLikeSmtp(string evidence) =>
        evidence.StartsWith("220", StringComparison.Ordinal)
        && ContainsAny(evidence, " ESMTP", " SMTP", "Postfix", "Exim", "Sendmail");

    private static bool LooksLikePop3(string evidence) =>
        evidence.StartsWith("+OK", StringComparison.OrdinalIgnoreCase)
        && ContainsAny(evidence, "POP3", "Dovecot", "Courier");

    private static bool LooksLikeImap(string evidence) =>
        evidence.StartsWith("* OK", StringComparison.OrdinalIgnoreCase)
        && ContainsAny(evidence, "IMAP", "Dovecot", "Courier");

    private static bool ContainsAny(string value, params string[] patterns) =>
        patterns.Any(pattern => value.Contains(pattern, StringComparison.OrdinalIgnoreCase));

    private static void CopyHeader(
        IReadOnlyDictionary<string, string> headers,
        IDictionary<string, string> attributes,
        string headerName,
        string attributeName)
    {
        if (headers.TryGetValue(headerName, out var value))
        {
            attributes[attributeName] = value;
        }
    }

    private static string? HeaderEvidence(
        IReadOnlyDictionary<string, string> headers,
        string headerName) =>
        headers.TryGetValue(headerName, out var value)
            ? string.Create(CultureInfo.InvariantCulture, $"{headerName}: {value}")
            : null;

    private static Regex CreateRegex(string pattern) =>
        new(
            pattern,
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase,
            RegexTimeout);

    private static IReadOnlySet<string> ProductSet(params string[] products) =>
        new HashSet<string>(products, StringComparer.Ordinal);

    private sealed record ProductPattern(string Product, Regex Pattern);
}
