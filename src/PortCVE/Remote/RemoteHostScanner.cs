using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PortCVE.Remote;

internal sealed class RemoteHostScanner : IRemoteHostScanner
{
    private static readonly (string Method, string Path, RemoteFingerprintKind Kind, string Source)[] ActiveHttpProbes = [
        ("OPTIONS", "/", RemoteFingerprintKind.HttpOptions, "active-http-options"),
        ("HEAD", "/robots.txt", RemoteFingerprintKind.HttpEndpoint, "active-http-head:robots.txt"),
        ("HEAD", "/.well-known/security.txt", RemoteFingerprintKind.HttpEndpoint, "active-http-head:security.txt"),
    ];

    private static readonly (SslProtocols Protocol, string Label)[] ActiveTlsProtocols = [
        (SslProtocols.Tls12, "TLS 1.2"),
        (SslProtocols.Tls13, "TLS 1.3"),
    ];

    private readonly IRemoteDnsResolver dnsResolver;
    private readonly RemoteProbePolicy probePolicy;
    private readonly Func<int, IRemoteConnectionRateLimiter> rateLimiterFactory;
    private readonly object rateLimiterSync = new();
    private IRemoteConnectionRateLimiter? sharedRateLimiter;
    private int? sharedConnectionRate;

    public RemoteHostScanner()
        : this(
            new SystemRemoteDnsResolver(),
            new RemoteProbePolicy(),
            static maximumConnectionsPerSecond =>
                new MonotonicConnectionRateLimiter(maximumConnectionsPerSecond))
    {
    }

    internal RemoteHostScanner(
        IRemoteDnsResolver dnsResolver,
        RemoteProbePolicy probePolicy,
        Func<int, IRemoteConnectionRateLimiter>? rateLimiterFactory = null)
    {
        this.dnsResolver = dnsResolver ?? throw new ArgumentNullException(nameof(dnsResolver));
        this.probePolicy = probePolicy ?? throw new ArgumentNullException(nameof(probePolicy));
        this.rateLimiterFactory = rateLimiterFactory
            ?? (static maximumConnectionsPerSecond =>
                new MonotonicConnectionRateLimiter(maximumConnectionsPerSecond));
    }

    public async Task<RemoteHostReport> ScanAsync(
        RemoteScanOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();

        IPAddress[] resolved;
        try
        {
            resolved = await dnsResolver.ResolveAsync(options.Target, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SocketException exception)
        {
            return EmptyReport(
                options.Target,
                new("dns_resolution_failed", SafeMessage(exception.Message)));
        }
        catch (ArgumentException exception)
        {
            return EmptyReport(
                options.Target,
                new("dns_resolution_failed", SafeMessage(exception.Message)));
        }

        var addresses = resolved
            .Where(static address => address.AddressFamily is
                AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            .Distinct(IPAddressValueComparer.Instance)
            .OrderBy(static address => address.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ThenBy(static address => Convert.ToHexString(address.GetAddressBytes()), StringComparer.Ordinal)
            .ThenBy(static address => address.AddressFamily == AddressFamily.InterNetworkV6
                ? address.ScopeId
                : 0)
            .ToArray();
        if (addresses.Length == 0)
        {
            return EmptyReport(
                options.Target,
                new("dns_no_addresses", "The target did not resolve to an IPv4 or IPv6 address."));
        }

        // The resolver is never called after this point. Every connection uses one of these
        // immutable numeric addresses, preventing mid-scan DNS changes from retargeting probes.
        var resolvedAddressStrings = addresses
            .Select(static address => address.ToString())
            .ToArray();
        var endpointCount = (long)addresses.Length * options.Ports.Count;
        if (endpointCount > RemoteScanOptions.MaximumEndpointCount)
        {
            return new(
                options.Target,
                resolvedAddressStrings,
                [],
                [new(
                    "scan_endpoint_limit_exceeded",
                    $"The frozen address and port set contains {endpointCount.ToString(CultureInfo.InvariantCulture)} "
                    + $"endpoints; the safety limit is {RemoteScanOptions.MaximumEndpointCount.ToString(CultureInfo.InvariantCulture)}.")]);
        }

        var endpoints = addresses
            .SelectMany(address => options.Ports.Select(port => new IPEndPoint(address, port)))
            .ToArray();
        var results = new RemotePortResult[endpoints.Length];
        var rateLimiter = GetSharedRateLimiter(options.MaxConnectionsPerSecond);
        var parallelOptions = new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = options.Concurrency,
        };

        await Parallel.ForEachAsync(
            Enumerable.Range(0, endpoints.Length),
            parallelOptions,
            async (index, token) =>
            {
                results[index] = await ScanEndpointAsync(
                    options,
                    endpoints[index],
                    rateLimiter,
                    token);
            });

        return new(
            options.Target,
            resolvedAddressStrings,
            results,
            []);
    }

    private async Task<RemotePortResult> ScanEndpointAsync(
        RemoteScanOptions options,
        IPEndPoint endpoint,
        IRemoteConnectionRateLimiter rateLimiter,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var fingerprints = new List<RemoteFingerprint>();
        var candidates = new List<RemoteProductCandidate>();
        var diagnostics = new List<RemoteDiagnostic>();
        var budget = new RemoteByteBudget(options.MaximumEvidenceBytes);
        var connection = await ConnectAsync(
            endpoint,
            options.ConnectTimeout,
            rateLimiter,
            cancellationToken);

        if (connection.Client is null)
        {
            if (connection.Diagnostic is not null)
            {
                diagnostics.Add(connection.Diagnostic);
            }

            return CreatePortResult(
                endpoint,
                connection.State,
                stopwatch.ElapsedMilliseconds,
                fingerprints,
                candidates,
                diagnostics);
        }

        var runAdaptiveProtocolProbes = false;
        using (connection.Client)
        {
            if (probePolicy.TlsPorts.Contains(endpoint.Port))
            {
                var tlsProbe = await ProbeTlsAsync(
                    connection.Client,
                    options,
                    endpoint,
                    budget,
                    fingerprints,
                    candidates,
                    diagnostics,
                    cancellationToken);
                if (tlsProbe.TlsConfirmed && options.ProbeDepth == ProbeDepth.Active)
                {
                    await RunActiveTlsProbesAsync(
                        options,
                        endpoint,
                        tlsProbe.HttpConfirmed,
                        rateLimiter,
                        budget,
                        fingerprints,
                        candidates,
                        diagnostics,
                        cancellationToken);
                }
            }
            else if (probePolicy.HttpPorts.Contains(endpoint.Port))
            {
                var httpConfirmed = await ProbeHttpAsync(
                    connection.Client.GetStream(),
                    options,
                    endpoint,
                    "HEAD",
                    "/",
                    RemoteFingerprintKind.Http,
                    "passive-http-head",
                    budget,
                    fingerprints,
                    candidates,
                    diagnostics,
                    cancellationToken);
                if (httpConfirmed && options.ProbeDepth == ProbeDepth.Active)
                {
                    await RunActiveHttpProbesAsync(
                        options,
                        endpoint,
                        useTls: false,
                        rateLimiter,
                        budget,
                        fingerprints,
                        candidates,
                        diagnostics,
                        cancellationToken);
                }
            }
            else
            {
                var greeting = await ReadAndAnalyzeGreetingAsync(
                    connection.Client.GetStream(),
                    options,
                    budget,
                    fingerprints,
                    candidates,
                    diagnostics,
                    cancellationToken);
                runAdaptiveProtocolProbes = options.ProbeDepth == ProbeDepth.Active
                    && !greeting.ReceivedBytes;
            }
        }

        // Unknown ports are deliberately passive-first. Sending an HTTP request or a TLS
        // ClientHello to an arbitrary protocol can be surprising, so the adaptive fallback
        // is available only in the explicitly authorized active profile. Each probe gets a
        // fresh connection after the greeting socket is closed and therefore still passes
        // through the shared connection-rate limiter and configured timeout controls.
        if (runAdaptiveProtocolProbes)
        {
            await RunAdaptiveProtocolProbesAsync(
                options,
                endpoint,
                rateLimiter,
                budget,
                fingerprints,
                candidates,
                diagnostics,
                cancellationToken);
        }

        return CreatePortResult(
            endpoint,
            RemotePortState.Open,
            stopwatch.ElapsedMilliseconds,
            fingerprints,
            candidates,
            diagnostics);
    }

    private async Task<InitialTlsProbeResult> ProbeTlsAsync(
        TcpClient client,
        RemoteScanOptions options,
        IPEndPoint endpoint,
        RemoteByteBudget budget,
        ICollection<RemoteFingerprint> fingerprints,
        ICollection<RemoteProductCandidate> candidates,
        ICollection<RemoteDiagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        var handshake = await AuthenticateTlsAsync(
            client,
            options.Target,
            options.ReadTimeout,
            SslProtocols.None,
            advertiseHttp11: probePolicy.HttpsPorts.Contains(endpoint.Port),
            cancellationToken);
        if (handshake.Stream is null)
        {
            diagnostics.Add(new(
                handshake.TimedOut ? "tls_handshake_timeout" : "tls_handshake_failed",
                handshake.Error ?? "The TLS handshake did not complete."));
            return new(false, false);
        }

        var httpConfirmed = false;
        using (handshake.Stream)
        using (handshake.Certificate)
        {
            AddTlsFingerprint(
                handshake,
                budget,
                fingerprints,
                diagnostics);
            if (probePolicy.HttpsPorts.Contains(endpoint.Port))
            {
                httpConfirmed = await ProbeHttpAsync(
                    handshake.Stream,
                    options,
                    endpoint,
                    "HEAD",
                    "/",
                    RemoteFingerprintKind.Http,
                    "passive-https-head",
                    budget,
                    fingerprints,
                    candidates,
                    diagnostics,
                    cancellationToken);
            }
            else
            {
                await ReadAndAnalyzeGreetingAsync(
                    handshake.Stream,
                    options,
                    budget,
                    fingerprints,
                    candidates,
                    diagnostics,
                    cancellationToken);
            }
        }

        return new(true, httpConfirmed);
    }

    private async Task RunAdaptiveProtocolProbesAsync(
        RemoteScanOptions options,
        IPEndPoint endpoint,
        IRemoteConnectionRateLimiter rateLimiter,
        RemoteByteBudget budget,
        ICollection<RemoteFingerprint> fingerprints,
        ICollection<RemoteProductCandidate> candidates,
        ICollection<RemoteDiagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        if (budget.Remaining == 0)
        {
            diagnostics.Add(new(
                "evidence_budget_exhausted",
                "The per-port evidence byte limit was reached before adaptive protocol probes ran."));
            return;
        }

        var httpConnection = await ConnectAsync(
            endpoint,
            options.ConnectTimeout,
            rateLimiter,
            cancellationToken);
        if (httpConnection.Client is null)
        {
            diagnostics.Add(new(
                "adaptive_http_connect_failed",
                httpConnection.Diagnostic?.Message ?? "The adaptive HTTP connection failed."));
        }
        else
        {
            using (httpConnection.Client)
            {
                var httpConfirmed = await ProbeHttpAsync(
                    httpConnection.Client.GetStream(),
                    options,
                    endpoint,
                    "HEAD",
                    "/",
                    RemoteFingerprintKind.Http,
                    "active-adaptive-http-head",
                    budget,
                    fingerprints,
                    candidates,
                    diagnostics,
                    cancellationToken);
                if (httpConfirmed)
                {
                    return;
                }
            }
        }

        var tlsConnection = await ConnectAsync(
            endpoint,
            options.ConnectTimeout,
            rateLimiter,
            cancellationToken);
        if (tlsConnection.Client is null)
        {
            diagnostics.Add(new(
                "adaptive_tls_connect_failed",
                tlsConnection.Diagnostic?.Message ?? "The adaptive TLS connection failed."));
            return;
        }

        using (tlsConnection.Client)
        {
            var handshake = await AuthenticateTlsAsync(
                tlsConnection.Client,
                options.Target,
                options.ReadTimeout,
                SslProtocols.None,
                advertiseHttp11: true,
                cancellationToken);
            using (handshake.Stream)
            using (handshake.Certificate)
            {
                if (handshake.Stream is null)
                {
                    diagnostics.Add(new(
                        handshake.TimedOut
                            ? "adaptive_tls_handshake_timeout"
                            : "adaptive_tls_handshake_failed",
                        handshake.Error ?? "The adaptive TLS handshake did not complete."));
                    return;
                }

                AddTlsFingerprint(
                    handshake,
                    budget,
                    fingerprints,
                    diagnostics,
                    "active-adaptive-tls-handshake");

                // ALPN is strong protocol evidence. Reuse the authenticated stream for one
                // safe HEAD only when the peer explicitly selected HTTP/1.1; a generic TLS
                // service is never promoted to HTTPS from its port number or certificate.
                if (handshake.Stream.NegotiatedApplicationProtocol == SslApplicationProtocol.Http11)
                {
                    await ProbeHttpAsync(
                        handshake.Stream,
                        options,
                        endpoint,
                        "HEAD",
                        "/",
                        RemoteFingerprintKind.Http,
                        "active-adaptive-https-head",
                        budget,
                        fingerprints,
                        candidates,
                        diagnostics,
                        cancellationToken);
                }
            }
        }
    }

    private async Task RunActiveTlsProbesAsync(
        RemoteScanOptions options,
        IPEndPoint endpoint,
        bool runHttpProbes,
        IRemoteConnectionRateLimiter rateLimiter,
        RemoteByteBudget budget,
        ICollection<RemoteFingerprint> fingerprints,
        ICollection<RemoteProductCandidate> candidates,
        ICollection<RemoteDiagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        foreach (var protocol in ActiveTlsProtocols)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var connection = await ConnectAsync(
                endpoint,
                options.ConnectTimeout,
                rateLimiter,
                cancellationToken);
            if (connection.Client is null)
            {
                diagnostics.Add(new(
                    "active_tls_connect_failed",
                    $"{protocol.Label} probe: {connection.Diagnostic?.Message ?? "connection failed"}"));
                continue;
            }

            using (connection.Client)
            {
                var handshake = await AuthenticateTlsAsync(
                    connection.Client,
                    options.Target,
                    options.ReadTimeout,
                    protocol.Protocol,
                    advertiseHttp11: false,
                    cancellationToken);
                using (handshake.Stream)
                using (handshake.Certificate)
                {
                    var attributes = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["requestedProtocol"] = protocol.Label,
                        ["outcome"] = handshake.Stream is null ? "handshake_failed" : "accepted",
                    };
                    string evidence;
                    RemoteFingerprintConfidence confidence;
                    if (handshake.Stream is not null)
                    {
                        attributes["negotiatedProtocol"] = handshake.Stream.SslProtocol.ToString();
                        attributes["cipherSuite"] = handshake.Stream.NegotiatedCipherSuite.ToString();
                        evidence = $"{protocol.Label} handshake completed; negotiated "
                            + $"{handshake.Stream.SslProtocol}; cipher {handshake.Stream.NegotiatedCipherSuite}.";
                        confidence = RemoteFingerprintConfidence.ProtocolConfirmed;
                    }
                    else
                    {
                        evidence = $"{protocol.Label} handshake did not complete; "
                            + "this does not prove that the server rejected the protocol. "
                            + (handshake.Error ?? string.Empty);
                        confidence = RemoteFingerprintConfidence.Observed;
                    }

                    var fingerprint = CreateBudgetedFingerprint(
                        RemoteFingerprintKind.TlsProtocolProbe,
                        "tls-probe",
                        confidence,
                        $"active-tls:{protocol.Label.Replace(' ', '-').ToLowerInvariant()}",
                        evidence,
                        attributes,
                        budget,
                        out var evidenceTruncated);
                    if (fingerprint is not null)
                    {
                        fingerprints.Add(fingerprint);
                        if (evidenceTruncated)
                        {
                            diagnostics.Add(new(
                                "evidence_budget_truncated",
                                "TLS posture evidence was truncated at the per-port evidence byte limit."));
                        }
                    }
                    else
                    {
                        diagnostics.Add(new(
                            "evidence_budget_exhausted",
                            "The per-port evidence byte limit was reached before TLS posture evidence could be retained."));
                    }
                }
            }
        }

        if (runHttpProbes && probePolicy.HttpsPorts.Contains(endpoint.Port))
        {
            await RunActiveHttpProbesAsync(
                options,
                endpoint,
                useTls: true,
                rateLimiter,
                budget,
                fingerprints,
                candidates,
                diagnostics,
                cancellationToken);
        }
    }

    private async Task RunActiveHttpProbesAsync(
        RemoteScanOptions options,
        IPEndPoint endpoint,
        bool useTls,
        IRemoteConnectionRateLimiter rateLimiter,
        RemoteByteBudget budget,
        ICollection<RemoteFingerprint> fingerprints,
        ICollection<RemoteProductCandidate> candidates,
        ICollection<RemoteDiagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        foreach (var probe in ActiveHttpProbes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (budget.Remaining == 0)
            {
                diagnostics.Add(new(
                    "evidence_budget_exhausted",
                    "The per-port evidence byte limit was reached before every active HTTP probe ran."));
                return;
            }

            var connection = await ConnectAsync(
                endpoint,
                options.ConnectTimeout,
                rateLimiter,
                cancellationToken);
            if (connection.Client is null)
            {
                diagnostics.Add(new(
                    "active_http_connect_failed",
                    $"{probe.Method} {probe.Path}: {connection.Diagnostic?.Message ?? "connection failed"}"));
                continue;
            }

            using (connection.Client)
            {
                if (useTls)
                {
                    var handshake = await AuthenticateTlsAsync(
                        connection.Client,
                        options.Target,
                        options.ReadTimeout,
                        SslProtocols.None,
                        advertiseHttp11: true,
                        cancellationToken);
                    using (handshake.Stream)
                    using (handshake.Certificate)
                    {
                        if (handshake.Stream is null)
                        {
                            diagnostics.Add(new(
                                "active_https_handshake_failed",
                                $"{probe.Method} {probe.Path}: "
                                + (handshake.Error ?? "TLS handshake failed")));
                            continue;
                        }

                        await ProbeHttpAsync(
                            handshake.Stream,
                            options,
                            endpoint,
                            probe.Method,
                            probe.Path,
                            probe.Kind,
                            probe.Source,
                            budget,
                            fingerprints,
                            candidates,
                            diagnostics,
                            cancellationToken);
                    }
                }
                else
                {
                    await ProbeHttpAsync(
                        connection.Client.GetStream(),
                        options,
                        endpoint,
                        probe.Method,
                        probe.Path,
                        probe.Kind,
                        probe.Source,
                        budget,
                        fingerprints,
                        candidates,
                        diagnostics,
                        cancellationToken);
                }
            }
        }
    }

    private static async Task<bool> ProbeHttpAsync(
        Stream stream,
        RemoteScanOptions options,
        IPEndPoint endpoint,
        string method,
        string path,
        RemoteFingerprintKind kind,
        string source,
        RemoteByteBudget budget,
        ICollection<RemoteFingerprint> fingerprints,
        ICollection<RemoteProductCandidate> candidates,
        ICollection<RemoteDiagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        if (budget.Remaining == 0)
        {
            diagnostics.Add(new(
                "evidence_budget_exhausted",
                "The per-port evidence byte limit was reached before the HTTP response was read."));
            return false;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.ReadTimeout);
        try
        {
            var request = BuildHttpRequest(method, path, options.Target, endpoint.Port);
            await stream.WriteAsync(request, timeout.Token);
            await stream.FlushAsync(timeout.Token);
            var response = await ReadHeaderBlockAsync(stream, budget, timeout.Token);
            var analysis = RemoteFingerprintParser.AnalyzeHttpResponse(
                Encoding.UTF8.GetString(response.Bytes),
                kind,
                source,
                options.MaximumEvidenceBytes,
                response.Complete);
            if (analysis.Fingerprints.Count == 0)
            {
                diagnostics.Add(new(
                    "http_response_unrecognized",
                    $"{method} {path} did not return a valid bounded HTTP/1.x status line."));
                return false;
            }

            AddAnalysis(analysis, fingerprints, candidates);
            if (!response.Complete)
            {
                diagnostics.Add(new(
                    response.LimitReached ? "http_header_limit_reached" : "http_headers_incomplete",
                    response.LimitReached
                        ? "The HTTP header block reached the remaining per-port evidence byte limit."
                        : "The connection ended before the HTTP header block terminator was observed."));
            }

            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            diagnostics.Add(new("http_probe_timeout", $"{method} {path} exceeded the read timeout."));
            return false;
        }
        catch (Exception exception) when (exception is IOException or AuthenticationException)
        {
            diagnostics.Add(new("http_probe_failed", SafeMessage(exception.Message)));
            return false;
        }
        catch (SocketException exception)
        {
            diagnostics.Add(new("http_probe_failed", SafeMessage(exception.Message)));
            return false;
        }
    }

    private static async Task<GreetingProbeResult> ReadAndAnalyzeGreetingAsync(
        Stream stream,
        RemoteScanOptions options,
        RemoteByteBudget budget,
        ICollection<RemoteFingerprint> fingerprints,
        ICollection<RemoteProductCandidate> candidates,
        ICollection<RemoteDiagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        if (budget.Remaining == 0)
        {
            return new(false);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.ReadTimeout);
        try
        {
            var greeting = await ReadGreetingAsync(
                stream,
                budget,
                timeout.Token,
                cancellationToken);
            var analysis = RemoteFingerprintParser.AnalyzeGreeting(
                RemoteEvidenceSanitizer.Sanitize(greeting.Bytes, options.MaximumEvidenceBytes),
                options.MaximumEvidenceBytes,
                greeting.Complete);
            AddAnalysis(analysis, fingerprints, candidates);
            if (greeting.Bytes.Length > 0 && !greeting.Complete)
            {
                diagnostics.Add(new(
                    greeting.LimitReached ? "greeting_limit_reached" : "greeting_incomplete",
                    greeting.LimitReached
                        ? "The greeting reached the remaining per-port evidence byte limit."
                        : "The connection ended before a complete greeting line was observed."));
            }

            return new(greeting.Bytes.Length > 0);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // An open service that does not speak first is a normal observation, not a failure.
            return new(false);
        }
        catch (Exception exception) when (exception is IOException or AuthenticationException)
        {
            // A peer may close an otherwise successful TCP connection without a greeting.
            return new(false);
        }
        catch (SocketException)
        {
            // A reset after connect does not change the observed open TCP state.
            return new(false);
        }
    }

    private static async Task<TlsHandshakeResult> AuthenticateTlsAsync(
        TcpClient client,
        string target,
        TimeSpan readTimeout,
        SslProtocols protocols,
        bool advertiseHttp11,
        CancellationToken cancellationToken)
    {
        X509Certificate2? capturedCertificate = null;
        var policyErrors = SslPolicyErrors.None;
        var stream = new SslStream(
            client.GetStream(),
            leaveInnerStreamOpen: false,
            (_, certificate, _, errors) =>
            {
                capturedCertificate?.Dispose();
                capturedCertificate = certificate is null
                    ? null
                    : new X509Certificate2(certificate);
                policyErrors = errors;
                return true;
            });
        var authenticationOptions = new SslClientAuthenticationOptions
        {
            TargetHost = target,
            EnabledSslProtocols = protocols,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            CertificateChainPolicy = new X509ChainPolicy
            {
                DisableCertificateDownloads = true,
                RevocationMode = X509RevocationMode.NoCheck,
            },
        };
        if (advertiseHttp11)
        {
            authenticationOptions.ApplicationProtocols = [SslApplicationProtocol.Http11];
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(readTimeout);
        try
        {
            await stream.AuthenticateAsClientAsync(authenticationOptions, timeout.Token);
            return new(stream, capturedCertificate, policyErrors, false, null);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            stream.Dispose();
            capturedCertificate?.Dispose();
            return new(null, null, policyErrors, true, "TLS authentication exceeded the read timeout.");
        }
        catch (OperationCanceledException)
        {
            stream.Dispose();
            capturedCertificate?.Dispose();
            throw;
        }
        catch (Exception exception) when (exception is
            AuthenticationException or IOException or SocketException or PlatformNotSupportedException)
        {
            stream.Dispose();
            capturedCertificate?.Dispose();
            return new(null, null, policyErrors, false, SafeMessage(exception.Message));
        }
    }

    private static void AddTlsFingerprint(
        TlsHandshakeResult handshake,
        RemoteByteBudget budget,
        ICollection<RemoteFingerprint> fingerprints,
        ICollection<RemoteDiagnostic> diagnostics,
        string source = "passive-tls-handshake")
    {
        var fingerprint = CreateTlsFingerprint(handshake, budget, source, out var evidenceTruncated);
        if (fingerprint is not null)
        {
            fingerprints.Add(fingerprint);
            if (evidenceTruncated)
            {
                diagnostics.Add(new(
                    "evidence_budget_truncated",
                    "TLS evidence was truncated at the per-port evidence byte limit."));
            }

            return;
        }

        diagnostics.Add(new(
            "evidence_budget_exhausted",
            "The per-port evidence byte limit was reached before TLS evidence could be retained."));
    }

    private static RemoteFingerprint? CreateTlsFingerprint(
        TlsHandshakeResult handshake,
        RemoteByteBudget budget,
        string source,
        out bool evidenceTruncated)
    {
        var stream = handshake.Stream
            ?? throw new ArgumentException("A completed TLS stream is required.", nameof(handshake));
        var attributes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["protocol"] = stream.SslProtocol.ToString(),
            ["cipherSuite"] = stream.NegotiatedCipherSuite.ToString(),
            ["certificatePolicyErrors"] = handshake.PolicyErrors.ToString(),
        };
        if (!stream.NegotiatedApplicationProtocol.Protocol.IsEmpty)
        {
            attributes["applicationProtocol"] = Encoding.ASCII.GetString(
                stream.NegotiatedApplicationProtocol.Protocol.Span);
        }
        var certificate = handshake.Certificate;
        if (certificate is not null)
        {
            attributes["certificateSubject"] = certificate.Subject;
            attributes["certificateIssuer"] = certificate.Issuer;
            attributes["certificateSha256"] = certificate.GetCertHashString(HashAlgorithmName.SHA256);
            attributes["certificateNotBeforeUtc"] = certificate.NotBefore
                .ToUniversalTime()
                .ToString("O", CultureInfo.InvariantCulture);
            attributes["certificateNotAfterUtc"] = certificate.NotAfter
                .ToUniversalTime()
                .ToString("O", CultureInfo.InvariantCulture);
            var dnsName = certificate.GetNameInfo(X509NameType.DnsName, forIssuer: false);
            if (!string.IsNullOrWhiteSpace(dnsName))
            {
                attributes["certificateDnsName"] = dnsName;
            }
        }

        var evidence = $"Negotiated {stream.SslProtocol}; cipher {stream.NegotiatedCipherSuite}; "
            + $"certificate policy errors {handshake.PolicyErrors}.";
        if (certificate is not null)
        {
            evidence += $" Certificate SHA-256 {certificate.GetCertHashString(HashAlgorithmName.SHA256)}; "
                + $"valid {certificate.NotBefore.ToUniversalTime():O} "
                + $"through {certificate.NotAfter.ToUniversalTime():O}.";
        }

        return CreateBudgetedFingerprint(
            RemoteFingerprintKind.Tls,
            "tls",
            RemoteFingerprintConfidence.ProtocolConfirmed,
            source,
            evidence,
            attributes,
            budget,
            out evidenceTruncated);
    }

    private static RemoteFingerprint? CreateBudgetedFingerprint(
        RemoteFingerprintKind kind,
        string service,
        RemoteFingerprintConfidence confidence,
        string source,
        string evidence,
        IReadOnlyDictionary<string, string> attributes,
        RemoteByteBudget budget,
        out bool evidenceTruncated)
    {
        evidenceTruncated = false;
        if (budget.Remaining == 0)
        {
            evidenceTruncated = true;
            return null;
        }

        var boundedAttributes = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var attribute in attributes)
        {
            if (budget.Remaining == 0)
            {
                evidenceTruncated = true;
                break;
            }

            var value = ConsumeSanitizedText(
                attribute.Value,
                budget,
                out var attributeTruncated);
            evidenceTruncated |= attributeTruncated;
            if (value.Length > 0)
            {
                boundedAttributes[attribute.Key] = value;
            }
        }

        var boundedEvidence = ConsumeSanitizedText(
            evidence,
            budget,
            out var bodyTruncated);
        evidenceTruncated |= bodyTruncated;
        if (boundedAttributes.Count == 0 && boundedEvidence.Length == 0)
        {
            return null;
        }

        return new(
            kind,
            service,
            confidence,
            source,
            boundedEvidence,
            RemoteFingerprint.ReadOnlyAttributes(boundedAttributes));
    }

    private static string ConsumeSanitizedText(
        string? value,
        RemoteByteBudget budget,
        out bool truncated)
    {
        var fullValue = RemoteEvidenceSanitizer.Sanitize(value, int.MaxValue);
        var sanitized = RemoteEvidenceSanitizer.Sanitize(fullValue, budget.Remaining);
        truncated = Encoding.UTF8.GetByteCount(sanitized) < Encoding.UTF8.GetByteCount(fullValue);
        budget.Consume(Encoding.UTF8.GetByteCount(sanitized));
        return sanitized;
    }

    private static async Task<ConnectionResult> ConnectAsync(
        IPEndPoint endpoint,
        TimeSpan connectTimeout,
        IRemoteConnectionRateLimiter rateLimiter,
        CancellationToken cancellationToken)
    {
        await rateLimiter.WaitAsync(cancellationToken);
        var client = new TcpClient(endpoint.AddressFamily)
        {
            NoDelay = true,
        };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(connectTimeout);
        try
        {
            await client.ConnectAsync(endpoint.Address, endpoint.Port, timeout.Token);
            return new(client, RemotePortState.Open, null);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            client.Dispose();
            return new(
                null,
                RemotePortState.TimedOut,
                new("connect_timeout", "The TCP connection attempt exceeded the configured timeout."));
        }
        catch (SocketException exception)
        {
            client.Dispose();
            var state = exception.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => RemotePortState.Closed,
                SocketError.TimedOut => RemotePortState.TimedOut,
                SocketError.HostUnreachable or
                SocketError.NetworkUnreachable or
                SocketError.AddressNotAvailable or
                SocketError.HostNotFound => RemotePortState.Unreachable,
                _ => RemotePortState.Error,
            };
            return new(
                null,
                state,
                new($"connect_{exception.SocketErrorCode.ToString().ToLowerInvariant()}", SafeMessage(exception.Message)));
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static byte[] BuildHttpRequest(string method, string path, string target, int port)
    {
        var defaultPort = port is 80 or 443;
        var host = IPAddress.TryParse(target, out var address)
            ? address.AddressFamily == AddressFamily.InterNetworkV6
                ? $"[{address}]"
                : address.ToString()
            : target;
        if (!defaultPort)
        {
            host = string.Create(CultureInfo.InvariantCulture, $"{host}:{port}");
        }

        var request = string.Create(
            CultureInfo.InvariantCulture,
            $"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: PortCVE-Remote/1\r\nAccept: */*\r\nConnection: close\r\n\r\n");
        return Encoding.ASCII.GetBytes(request);
    }

    private static async Task<BoundedReadResult> ReadHeaderBlockAsync(
        Stream stream,
        RemoteByteBudget budget,
        CancellationToken cancellationToken)
    {
        using var output = new MemoryStream(Math.Min(budget.Remaining, 4_096));
        while (budget.Remaining > 0)
        {
            var buffer = new byte[Math.Min(1_024, budget.Remaining)];
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                break;
            }

            budget.Consume(read);
            output.Write(buffer, 0, read);
            var data = output.GetBuffer().AsSpan(0, checked((int)output.Length));
            var delimiter = FindHeaderDelimiter(data);
            if (delimiter > 0)
            {
                return new(data[..delimiter].ToArray(), true, false);
            }
        }

        return new(output.ToArray(), false, budget.Remaining == 0);
    }

    private static async Task<BoundedReadResult> ReadGreetingAsync(
        Stream stream,
        RemoteByteBudget budget,
        CancellationToken readCancellationToken,
        CancellationToken operationCancellationToken)
    {
        using var output = new MemoryStream(Math.Min(budget.Remaining, 1_024));
        while (budget.Remaining > 0)
        {
            var buffer = new byte[Math.Min(512, budget.Remaining)];
            int read;
            try
            {
                read = await stream.ReadAsync(buffer, readCancellationToken);
            }
            catch (OperationCanceledException) when (
                output.Length > 0
                && !operationCancellationToken.IsCancellationRequested)
            {
                // A read timeout after partial data is still positive evidence that
                // this service was not silent. Preserve it so adaptive cross-protocol
                // probes stay suppressed. A caller cancellation still propagates.
                break;
            }
            catch (Exception exception) when (
                output.Length > 0
                && exception is IOException or SocketException or AuthenticationException)
            {
                // Preserve bytes received before a peer reset/close. They are positive
                // evidence that the service was not silent and must suppress adaptive
                // cross-protocol probes, even when the greeting is incomplete.
                break;
            }

            if (read == 0)
            {
                break;
            }

            budget.Consume(read);
            var lineFeed = Array.IndexOf(buffer, (byte)'\n', 0, read);
            var captured = lineFeed >= 0 ? lineFeed + 1 : read;
            output.Write(buffer, 0, captured);
            if (lineFeed >= 0)
            {
                break;
            }
        }

        var complete = output.Length > 0 && output.GetBuffer()[output.Length - 1] == '\n';
        return new(output.ToArray(), complete, !complete && budget.Remaining == 0);
    }

    private static int FindHeaderDelimiter(ReadOnlySpan<byte> bytes)
    {
        for (var index = 0; index < bytes.Length - 1; index++)
        {
            if (bytes[index] == '\n' && bytes[index + 1] == '\n')
            {
                return index + 2;
            }

            if (index < bytes.Length - 3
                && bytes[index] == '\r'
                && bytes[index + 1] == '\n'
                && bytes[index + 2] == '\r'
                && bytes[index + 3] == '\n')
            {
                return index + 4;
            }
        }

        return -1;
    }

    private static void AddAnalysis(
        RemoteFingerprintAnalysis analysis,
        ICollection<RemoteFingerprint> fingerprints,
        ICollection<RemoteProductCandidate> candidates)
    {
        foreach (var fingerprint in analysis.Fingerprints)
        {
            fingerprints.Add(fingerprint);
        }

        foreach (var candidate in analysis.ProductCandidates)
        {
            candidates.Add(candidate);
        }
    }

    private static RemotePortResult CreatePortResult(
        IPEndPoint endpoint,
        RemotePortState state,
        long durationMs,
        IEnumerable<RemoteFingerprint> fingerprints,
        IEnumerable<RemoteProductCandidate> candidates,
        IEnumerable<RemoteDiagnostic> diagnostics) =>
        new(
            endpoint.Address.ToString(),
            endpoint.AddressFamily == AddressFamily.InterNetwork ? "ipv4" : "ipv6",
            endpoint.Port,
            state,
            durationMs,
            fingerprints.ToArray(),
            candidates
                .DistinctBy(static candidate => (
                    candidate.Product.ToUpperInvariant(),
                    candidate.Version?.ToUpperInvariant(),
                    candidate.Source.ToUpperInvariant()))
                .ToArray(),
            diagnostics.ToArray());

    private static RemoteHostReport EmptyReport(string target, RemoteDiagnostic diagnostic) =>
        new(target, [], [], [diagnostic]);

    private IRemoteConnectionRateLimiter GetSharedRateLimiter(int maximumConnectionsPerSecond)
    {
        lock (rateLimiterSync)
        {
            if (sharedRateLimiter is null)
            {
                sharedRateLimiter = rateLimiterFactory(maximumConnectionsPerSecond)
                    ?? throw new InvalidOperationException("The connection rate-limiter factory returned null.");
                sharedConnectionRate = maximumConnectionsPerSecond;
            }
            else if (sharedConnectionRate != maximumConnectionsPerSecond)
            {
                throw new InvalidOperationException(
                    "One RemoteHostScanner run must use a consistent MaxConnectionsPerSecond value.");
            }

            return sharedRateLimiter;
        }
    }

    private static string SafeMessage(string? message) =>
        RemoteEvidenceSanitizer.Sanitize(message ?? "Operation failed.", 512);

    private sealed record ConnectionResult(
        TcpClient? Client,
        RemotePortState State,
        RemoteDiagnostic? Diagnostic);

    private sealed record TlsHandshakeResult(
        SslStream? Stream,
        X509Certificate2? Certificate,
        SslPolicyErrors PolicyErrors,
        bool TimedOut,
        string? Error);

    private sealed record InitialTlsProbeResult(bool TlsConfirmed, bool HttpConfirmed);

    private sealed record GreetingProbeResult(bool ReceivedBytes);

    private sealed record BoundedReadResult(byte[] Bytes, bool Complete, bool LimitReached);

    private sealed class RemoteByteBudget(int maximumBytes)
    {
        public int Remaining { get; private set; } = maximumBytes;

        public void Consume(int bytes)
        {
            if (bytes < 0 || bytes > Remaining)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes));
            }

            Remaining -= bytes;
        }
    }

    private sealed class IPAddressValueComparer : IEqualityComparer<IPAddress>
    {
        public static IPAddressValueComparer Instance { get; } = new();

        public bool Equals(IPAddress? left, IPAddress? right) =>
            left is not null && right is not null && left.Equals(right);

        public int GetHashCode(IPAddress address) => address.GetHashCode();
    }
}
