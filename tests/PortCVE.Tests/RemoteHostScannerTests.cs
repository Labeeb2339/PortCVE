using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PortCVE.Remote;

namespace PortCVE.Tests;

public sealed class RemoteHostScannerTests
{
    [Fact]
    public async Task ScanAsync_FreezesResolutionConsultsRateLimiterAndFingerprintsGreeting()
    {
        var listener = StartListener(IPAddress.Loopback);
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = ServeGreetingAsync(
            listener,
            "SSH-2.0-OpenSSH_9.9p1 Test\0Control\r\n",
            serverCancellation.Token);
        var resolver = new RecordingDnsResolver(IPAddress.Loopback);
        var limiter = new RecordingRateLimiter();
        var requestedRate = 0;
        var scanner = new RemoteHostScanner(
            resolver,
            NoConventionalProbes(),
            rate =>
            {
                requestedRate = rate;
                return limiter;
            });
        var options = Options(
            "scanner.test",
            ListenerPort(listener),
            maxConnectionsPerSecond: 321);

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(options, serverCancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        Assert.Equal(1, resolver.CallCount);
        Assert.Equal("scanner.test", resolver.LastTarget);
        Assert.Equal(321, requestedRate);
        Assert.Equal(1, limiter.WaitCount);
        Assert.Equal(["127.0.0.1"], report.ResolvedAddresses);
        var port = Assert.Single(report.Ports);
        Assert.Equal(RemotePortState.Open, port.State);
        Assert.Equal("ipv4", port.AddressFamily);
        Assert.Equal(RemoteFingerprintKind.Ssh, Assert.Single(port.Fingerprints).Kind);
        Assert.DoesNotContain(port.Fingerprints[0].Evidence, static character => char.IsControl(character));
        var product = Assert.Single(port.ProductCandidates);
        Assert.Equal("OpenSSH", product.Product);
        Assert.Equal("9.9p1", product.Version);
    }

    [Theory]
    [InlineData("SSH-2.0-dropbear_2020.81\r\n", "Dropbear SSH", "2020.81")]
    [InlineData("220 ProFTPD 1.3.8a Server (fixture) [127.0.0.1]\r\n", "ProFTPD", "1.3.8a")]
    [InlineData("220 (vsFTPd 3.0.3)\r\n", "vsftpd", "3.0.3")]
    [InlineData("220 mail.example ESMTP Exim 4.98.2 Sun, 10 Aug 2026 00:00:00 +0000\r\n", "Exim", "4.98.2")]
    public async Task ScanAsync_LocalGreetingFixtureRetainsProtocolBoundCatalogIdentity(
        string greeting,
        string expectedProduct,
        string expectedVersion)
    {
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = ServeGreetingAsync(listener, greeting, cancellation.Token);
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            NoConventionalProbes(),
            _ => new RecordingRateLimiter());

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(
                Options("catalog-fixture.test", ListenerPort(listener)),
                cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        var product = Assert.Single(Assert.Single(report.Ports).ProductCandidates);
        Assert.Equal(expectedProduct, product.Product);
        Assert.Equal(expectedVersion, product.Version);
        Assert.Equal(RemoteProductConfidence.BannerPattern, product.Confidence);
        Assert.Equal("passive-greeting", product.Source);
    }

    [Fact]
    public async Task ScanAsync_HttpHeadDoesNotFollowRedirectOrRetainBody()
    {
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        string? requestLine = null;
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cancellation.Token);
            var request = await ReadRequestHeadersAsync(client.GetStream(), cancellation.Token);
            requestLine = FirstLine(request);
            var response = Encoding.ASCII.GetBytes(
                "HTTP/1.1 302 Found\r\n"
                + "Server: nginx/1.27.4\r\n"
                + "Location: https://redirect.invalid/\r\n"
                + "Content-Length: 18\r\n\r\n"
                + "sensitive-body-data");
            await client.GetStream().WriteAsync(response, cancellation.Token);
        }, cancellation.Token);
        var port = ListenerPort(listener);
        var limiter = new RecordingRateLimiter();
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            new RemoteProbePolicy([port], [], []),
            _ => limiter);

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(Options("web.test", port), cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        Assert.Equal("HEAD / HTTP/1.1", requestLine);
        Assert.Equal(1, limiter.WaitCount);
        var result = Assert.Single(report.Ports);
        var http = Assert.Single(result.Fingerprints);
        Assert.Equal(RemoteFingerprintKind.Http, http.Kind);
        Assert.Equal("302", http.Attributes["statusCode"]);
        Assert.DoesNotContain("sensitive-body-data", http.Evidence, StringComparison.Ordinal);
        var product = Assert.Single(result.ProductCandidates);
        Assert.Equal("nginx", product.Product);
        Assert.Equal("1.27.4", product.Version);
    }

    [Fact]
    public async Task ScanAsync_ActiveHttpUsesOnlyBoundedSafeMethodsAndEndpoints()
    {
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var requestLines = new ConcurrentQueue<string>();
        var server = ServeHttpConnectionsAsync(
            listener,
            connectionCount: 4,
            requestLines,
            cancellation.Token);
        var port = ListenerPort(listener);
        var limiter = new RecordingRateLimiter();
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            new RemoteProbePolicy([port], [], []),
            _ => limiter);
        var options = Options("active.test", port, ProbeDepth.Active, maximumEvidenceBytes: 8_192);

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(options, cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        Assert.Equal(
            [
                "HEAD / HTTP/1.1",
                "OPTIONS / HTTP/1.1",
                "HEAD /robots.txt HTTP/1.1",
                "HEAD /.well-known/security.txt HTTP/1.1",
            ],
            requestLines.ToArray());
        Assert.Equal(4, limiter.WaitCount);
        var result = Assert.Single(report.Ports);
        Assert.Equal(4, result.Fingerprints.Count);
        Assert.Contains(result.Fingerprints, static fingerprint =>
            fingerprint.Kind == RemoteFingerprintKind.HttpOptions);
        Assert.Equal(2, result.Fingerprints.Count(static fingerprint =>
            fingerprint.Kind == RemoteFingerprintKind.HttpEndpoint));
        Assert.DoesNotContain(requestLines, static line =>
            line.StartsWith("GET ", StringComparison.Ordinal)
            || line.StartsWith("POST ", StringComparison.Ordinal)
            || line.StartsWith("PUT ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ScanAsync_PassiveUnknownPortReadsGreetingWithoutSendingProtocolProbes()
    {
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var received = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cancellation.Token);
            return await ReadUntilPeerClosesAsync(client.GetStream(), cancellation.Token);
        }, cancellation.Token);
        var limiter = new RecordingRateLimiter();
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            NoConventionalProbes(),
            _ => limiter);

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(
                Options(
                    "passive-unknown.test",
                    ListenerPort(listener),
                    readTimeout: TimeSpan.FromMilliseconds(150)),
                cancellation.Token);
            Assert.Empty(await received);
        }
        finally
        {
            listener.Stop();
        }

        Assert.Equal(1, limiter.WaitCount);
        var result = Assert.Single(report.Ports);
        Assert.Equal(RemotePortState.Open, result.State);
        Assert.Empty(result.Fingerprints);
        Assert.Empty(result.ProductCandidates);
    }

    [Fact]
    public async Task ScanAsync_ActiveUnknownGreetingDoesNotTriggerCrossProtocolOrProductClaims()
    {
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = ServeGreetingAsync(
            listener,
            "NOTICE Server: nginx/1.27.4\r\n",
            cancellation.Token);
        var limiter = new RecordingRateLimiter();
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            NoConventionalProbes(),
            _ => limiter);

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(
                Options(
                    "unknown-greeting.test",
                    ListenerPort(listener),
                    ProbeDepth.Active,
                    readTimeout: TimeSpan.FromMilliseconds(200)),
                cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        Assert.Equal(1, limiter.WaitCount);
        var result = Assert.Single(report.Ports);
        var greeting = Assert.Single(result.Fingerprints);
        Assert.Equal(RemoteFingerprintKind.Greeting, greeting.Kind);
        Assert.Equal("unknown", greeting.Service);
        Assert.Empty(result.ProductCandidates);
    }

    [Fact]
    public async Task ScanAsync_ActiveFallbackDiscoversHttpOnAnArbitraryPort()
    {
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var requestLines = new ConcurrentQueue<string>();
        var firstConnectionBytes = new TaskCompletionSource<byte[]>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var server = Task.Run(async () =>
        {
            using (var greetingClient = await listener.AcceptTcpClientAsync(cancellation.Token))
            {
                firstConnectionBytes.SetResult(await ReadUntilPeerClosesAsync(
                    greetingClient.GetStream(),
                    cancellation.Token));
            }

            using var httpClient = await listener.AcceptTcpClientAsync(cancellation.Token);
            var stream = httpClient.GetStream();
            var request = await ReadRequestHeadersAsync(stream, cancellation.Token);
            requestLines.Enqueue(FirstLine(request));
            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nServer: nginx/1.27.4\r\nContent-Length: 0\r\n\r\n"),
                cancellation.Token);
        }, cancellation.Token);
        var limiter = new RecordingRateLimiter();
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            NoConventionalProbes(),
            _ => limiter);

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(
                Options(
                    "adaptive-http.test",
                    ListenerPort(listener),
                    ProbeDepth.Active,
                    readTimeout: TimeSpan.FromMilliseconds(200)),
                cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        Assert.Empty(await firstConnectionBytes.Task);
        Assert.Equal(["HEAD / HTTP/1.1"], requestLines.ToArray());
        Assert.Equal(2, limiter.WaitCount);
        var result = Assert.Single(report.Ports);
        var http = Assert.Single(result.Fingerprints);
        Assert.Equal(RemoteFingerprintKind.Http, http.Kind);
        Assert.Equal("active-adaptive-http-head", http.Source);
        var product = Assert.Single(result.ProductCandidates);
        Assert.Equal("nginx", product.Product);
        Assert.Equal("1.27.4", product.Version);
    }

    [Fact]
    public async Task ScanAsync_ActiveFallbackDiscoversTlsAndAlpnBoundHttpsOnAnArbitraryPort()
    {
        using var certificate = CreateServerCertificate();
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var clearRequestLines = new ConcurrentQueue<string>();
        var tlsRequestLines = new ConcurrentQueue<string>();
        var firstConnectionBytes = new TaskCompletionSource<byte[]>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var server = ServeAdaptiveHttpsConnectionsAsync(
            listener,
            certificate,
            firstConnectionBytes,
            clearRequestLines,
            tlsRequestLines,
            cancellation.Token);
        var limiter = new RecordingRateLimiter();
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            NoConventionalProbes(),
            _ => limiter);

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(
                Options(
                    "localhost",
                    ListenerPort(listener),
                    ProbeDepth.Active,
                    readTimeout: TimeSpan.FromMilliseconds(500)),
                cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        Assert.Empty(await firstConnectionBytes.Task);
        Assert.Equal(["HEAD / HTTP/1.1"], clearRequestLines.ToArray());
        Assert.Equal(["HEAD / HTTP/1.1"], tlsRequestLines.ToArray());
        Assert.Equal(3, limiter.WaitCount);
        var result = Assert.Single(report.Ports);
        var tls = Assert.Single(result.Fingerprints, static fingerprint =>
            fingerprint.Kind == RemoteFingerprintKind.Tls);
        Assert.Equal("active-adaptive-tls-handshake", tls.Source);
        Assert.Equal("http/1.1", tls.Attributes["applicationProtocol"]);
        var http = Assert.Single(result.Fingerprints, static fingerprint =>
            fingerprint.Kind == RemoteFingerprintKind.Http);
        Assert.Equal("active-adaptive-https-head", http.Source);
        var product = Assert.Single(result.ProductCandidates);
        Assert.Equal("Caddy", product.Product);
        Assert.Equal("2.8.4", product.Version);
    }

    [Fact]
    public async Task ScanAsync_MarksAnUnterminatedHttpHeaderBlockIncomplete()
    {
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cancellation.Token);
            _ = await ReadRequestHeadersAsync(client.GetStream(), cancellation.Token);
            await client.GetStream().WriteAsync(
                Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nServer: nginx/1.27.4\r\n"),
                cancellation.Token);
        }, cancellation.Token);
        var port = ListenerPort(listener);
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            new RemoteProbePolicy([port], [], []),
            _ => new RecordingRateLimiter());

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(Options("incomplete.test", port), cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        var result = Assert.Single(report.Ports);
        var http = Assert.Single(result.Fingerprints);
        Assert.Equal("false", http.Attributes["headersComplete"]);
        Assert.Contains(result.Diagnostics, static diagnostic =>
            diagnostic.Code == "http_headers_incomplete");
    }

    [Fact]
    public async Task ScanAsync_DoesNotPromoteAnUnterminatedSshGreeting()
    {
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = ServeGreetingAsync(
            listener,
            "SSH-2.0-OpenSSH_9.9p1",
            cancellation.Token);
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            NoConventionalProbes(),
            _ => new RecordingRateLimiter());

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(
                Options("incomplete-ssh.test", ListenerPort(listener)),
                cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        var result = Assert.Single(report.Ports);
        Assert.Equal(RemoteFingerprintKind.Greeting, Assert.Single(result.Fingerprints).Kind);
        Assert.Empty(result.ProductCandidates);
        Assert.Contains(result.Diagnostics, static diagnostic =>
            diagnostic.Code == "greeting_incomplete");
    }

    [Fact]
    public async Task ScanAsync_PartialGreetingThatStallsSuppressesAdaptiveProbes()
    {
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var followupConnections = 0;
        var server = Task.Run(async () =>
        {
            using (var greetingClient = await listener.AcceptTcpClientAsync(cancellation.Token))
            {
                await greetingClient.GetStream().WriteAsync(
                    Encoding.ASCII.GetBytes("SSH-"),
                    cancellation.Token);
                await Task.Delay(TimeSpan.FromMilliseconds(250), cancellation.Token);
            }

            using var followupCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                cancellation.Token);
            followupCancellation.CancelAfter(TimeSpan.FromMilliseconds(500));
            try
            {
                using var followup = await listener.AcceptTcpClientAsync(followupCancellation.Token);
                Interlocked.Increment(ref followupConnections);
            }
            catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
            {
                // No second connection is the expected safe behavior.
            }
        }, cancellation.Token);
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            NoConventionalProbes(),
            _ => new RecordingRateLimiter());

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(
                Options(
                    "slow-partial-greeting.test",
                    ListenerPort(listener),
                    ProbeDepth.Active,
                    readTimeout: TimeSpan.FromMilliseconds(100)),
                cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        var result = Assert.Single(report.Ports);
        Assert.Equal(RemoteFingerprintKind.Greeting, Assert.Single(result.Fingerprints).Kind);
        Assert.Empty(result.ProductCandidates);
        Assert.Equal(0, Volatile.Read(ref followupConnections));
        Assert.Contains(result.Diagnostics, static diagnostic =>
            diagnostic.Code == "greeting_incomplete");
    }

    [Fact]
    public async Task ScanAsync_TlsReportsCertificateAndHttpsHeaderEvidenceWithoutTrustClaim()
    {
        using var certificate = CreateServerCertificate();
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var requestLines = new ConcurrentQueue<string>();
        var server = ServeTlsConnectionsAsync(
            listener,
            certificate,
            connectionCount: 1,
            requestLines,
            cancellation.Token);
        var port = ListenerPort(listener);
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            new RemoteProbePolicy([], [port], [port]),
            _ => new RecordingRateLimiter());

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(Options("localhost", port), cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        Assert.True(
            requestLines.SequenceEqual(["HEAD / HTTP/1.1"]),
            string.Join(" | ", requestLines.Concat(
                report.Ports.SelectMany(static result => result.Diagnostics)
                    .Select(static diagnostic => $"{diagnostic.Code}: {diagnostic.Message}"))));
        var result = Assert.Single(report.Ports);
        var tls = Assert.Single(result.Fingerprints, static fingerprint =>
            fingerprint.Kind == RemoteFingerprintKind.Tls);
        Assert.Equal(certificate.GetCertHashString(HashAlgorithmName.SHA256),
            tls.Attributes["certificateSha256"]);
        Assert.Equal("tls", tls.Service);
        Assert.True(tls.Attributes.ContainsKey("certificatePolicyErrors"));
        var http = Assert.Single(result.Fingerprints, static fingerprint =>
            fingerprint.Kind == RemoteFingerprintKind.Http);
        Assert.Equal("200", http.Attributes["statusCode"]);
        var product = Assert.Single(result.ProductCandidates);
        Assert.Equal("Caddy", product.Product);
        Assert.Equal("2.8.4", product.Version);
    }

    [Fact]
    public async Task ScanAsync_ChargesTlsMetadataToThePerPortEvidenceBudget()
    {
        using var certificate = CreateServerCertificate();
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = ServeTlsConnectionsAsync(
            listener,
            certificate,
            connectionCount: 1,
            new ConcurrentQueue<string>(),
            cancellation.Token);
        var port = ListenerPort(listener);
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            new RemoteProbePolicy([], [port], []),
            _ => new RecordingRateLimiter());

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(
                Options("localhost", port, maximumEvidenceBytes: 256),
                cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        var result = Assert.Single(report.Ports);
        var tls = Assert.Single(
            result.Fingerprints,
            static fingerprint => fingerprint.Kind == RemoteFingerprintKind.Tls);
        var retainedBytes = Encoding.UTF8.GetByteCount(tls.Evidence)
            + tls.Attributes.Values.Sum(Encoding.UTF8.GetByteCount);
        Assert.InRange(retainedBytes, 1, 256);
        Assert.Contains(result.Diagnostics, static diagnostic =>
            diagnostic.Code == "evidence_budget_truncated");
    }

    [Fact]
    public async Task ScanAsync_ActiveTlsPostureAndHttpsChecksAreDistinctFromProducts()
    {
        using var certificate = CreateServerCertificate();
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var requestLines = new ConcurrentQueue<string>();
        var server = ServeTlsConnectionsAsync(
            listener,
            certificate,
            connectionCount: 6,
            requestLines,
            cancellation.Token);
        var port = ListenerPort(listener);
        var limiter = new RecordingRateLimiter();
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            new RemoteProbePolicy([], [port], [port]),
            _ => limiter);

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(
                Options("localhost", port, ProbeDepth.Active, maximumEvidenceBytes: 16_384),
                cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        Assert.Equal(6, limiter.WaitCount);
        var result = Assert.Single(report.Ports);
        Assert.Equal(2, result.Fingerprints.Count(static fingerprint =>
            fingerprint.Kind == RemoteFingerprintKind.TlsProtocolProbe));
        Assert.Contains(result.Fingerprints, static fingerprint =>
            fingerprint.Kind == RemoteFingerprintKind.HttpOptions);
        Assert.Equal(2, result.Fingerprints.Count(static fingerprint =>
            fingerprint.Kind == RemoteFingerprintKind.HttpEndpoint));
        Assert.All(result.ProductCandidates, static candidate =>
            Assert.Contains("http", candidate.Source, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(
            [
                "HEAD / HTTP/1.1",
                "OPTIONS / HTTP/1.1",
                "HEAD /robots.txt HTTP/1.1",
                "HEAD /.well-known/security.txt HTTP/1.1",
            ],
            requestLines.ToArray());
    }

    [Fact]
    public async Task ScanAsync_CapsGreetingEvidenceBytes()
    {
        var listener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = ServeGreetingAsync(
            listener,
            new string('A', 2_048),
            cancellation.Token);
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            NoConventionalProbes(),
            _ => new RecordingRateLimiter());

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(
                Options("bounded.test", ListenerPort(listener), maximumEvidenceBytes: 256),
                cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        var evidence = Assert.Single(Assert.Single(report.Ports).Fingerprints).Evidence;
        Assert.Equal(256, Encoding.UTF8.GetByteCount(evidence));
    }

    [Fact]
    public async Task ScanAsync_CallerCancellationInterruptsRateWait()
    {
        var limiter = new BlockingRateLimiter();
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            NoConventionalProbes(),
            _ => limiter);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scanner.ScanAsync(
            Options("cancel.test", 9),
            cancellation.Token));
        Assert.Equal(1, limiter.WaitCount);
    }

    [Fact]
    public async Task ScanAsync_ReusesOneRateLimiterAcrossSequentialTargets()
    {
        var firstListener = StartListener(IPAddress.Loopback);
        var secondListener = StartListener(IPAddress.Loopback);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var firstServer = ServeGreetingAsync(
            firstListener,
            "SSH-2.0-OpenSSH_9.9\r\n",
            cancellation.Token);
        var secondServer = ServeGreetingAsync(
            secondListener,
            "SSH-2.0-OpenSSH_9.9\r\n",
            cancellation.Token);
        var limiter = new RecordingRateLimiter();
        var factoryCalls = 0;
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.Loopback),
            NoConventionalProbes(),
            _ =>
            {
                Interlocked.Increment(ref factoryCalls);
                return limiter;
            });

        try
        {
            var first = await scanner.ScanAsync(
                Options("first.test", ListenerPort(firstListener), maxConnectionsPerSecond: 42),
                cancellation.Token);
            var second = await scanner.ScanAsync(
                Options("second.test", ListenerPort(secondListener), maxConnectionsPerSecond: 42),
                cancellation.Token);
            await Task.WhenAll(firstServer, secondServer);

            Assert.Equal(RemotePortState.Open, Assert.Single(first.Ports).State);
            Assert.Equal(RemotePortState.Open, Assert.Single(second.Ports).State);
        }
        finally
        {
            firstListener.Stop();
            secondListener.Stop();
        }

        Assert.Equal(1, Volatile.Read(ref factoryCalls));
        Assert.Equal(2, limiter.WaitCount);
    }

    [Fact]
    public async Task ScanAsync_RejectsAnExcessiveFrozenEndpointSetBeforeConnecting()
    {
        var addresses = Enumerable.Range(1, 5)
            .Select(index => IPAddress.Parse($"192.0.2.{index}"))
            .ToArray();
        var limiterFactoryCalls = 0;
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(addresses),
            NoConventionalProbes(),
            _ =>
            {
                Interlocked.Increment(ref limiterFactoryCalls);
                return new RecordingRateLimiter();
            });
        var options = new RemoteScanOptions(
            "bounded-target.test",
            Enumerable.Range(1, 65_535).ToArray(),
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromMilliseconds(100),
            concurrency: 4);

        var report = await scanner.ScanAsync(options, CancellationToken.None);

        Assert.Equal(5, report.ResolvedAddresses.Count);
        Assert.Empty(report.Ports);
        var diagnostic = Assert.Single(report.Diagnostics);
        Assert.Equal("scan_endpoint_limit_exceeded", diagnostic.Code);
        Assert.Equal(0, Volatile.Read(ref limiterFactoryCalls));
    }

    [Fact]
    public async Task ScanAsync_SupportsIpv6LoopbackWhenAvailable()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        TcpListener listener;
        try
        {
            listener = StartListener(IPAddress.IPv6Loopback);
        }
        catch (SocketException)
        {
            return;
        }

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = ServeGreetingAsync(
            listener,
            "SSH-2.0-OpenSSH_9.9\r\n",
            cancellation.Token);
        var scanner = new RemoteHostScanner(
            new RecordingDnsResolver(IPAddress.IPv6Loopback),
            NoConventionalProbes(),
            _ => new RecordingRateLimiter());

        RemoteHostReport report;
        try
        {
            report = await scanner.ScanAsync(
                Options("ipv6.test", ListenerPort(listener)),
                cancellation.Token);
            await server;
        }
        finally
        {
            listener.Stop();
        }

        var result = Assert.Single(report.Ports);
        Assert.Equal(RemotePortState.Open, result.State);
        Assert.Equal("ipv6", result.AddressFamily);
        Assert.Equal("::1", result.Address);
    }

    private static RemoteScanOptions Options(
        string target,
        int port,
        ProbeDepth probeDepth = ProbeDepth.Passive,
        int maximumEvidenceBytes = 8_192,
        int maxConnectionsPerSecond = 100,
        TimeSpan? readTimeout = null) =>
        new(
            target,
            [port],
            connectTimeout: TimeSpan.FromSeconds(2),
            readTimeout: readTimeout ?? TimeSpan.FromSeconds(2),
            concurrency: 4,
            probeDepth,
            maximumEvidenceBytes,
            maxConnectionsPerSecond);

    private static RemoteProbePolicy NoConventionalProbes() => new([], [], []);

    private static TcpListener StartListener(IPAddress address)
    {
        var listener = new TcpListener(address, 0);
        listener.Start();
        return listener;
    }

    private static int ListenerPort(TcpListener listener) =>
        ((IPEndPoint)listener.LocalEndpoint).Port;

    private static async Task ServeGreetingAsync(
        TcpListener listener,
        string greeting,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await client.GetStream().WriteAsync(Encoding.UTF8.GetBytes(greeting), cancellationToken);
    }

    private static async Task ServeHttpConnectionsAsync(
        TcpListener listener,
        int connectionCount,
        ConcurrentQueue<string> requestLines,
        CancellationToken cancellationToken)
    {
        for (var index = 0; index < connectionCount; index++)
        {
            using var client = await listener.AcceptTcpClientAsync(cancellationToken);
            var stream = client.GetStream();
            var request = await ReadRequestHeadersAsync(stream, cancellationToken);
            requestLines.Enqueue(FirstLine(request));
            var response = Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nServer: nginx/1.27.4\r\nAllow: HEAD, OPTIONS\r\nContent-Length: 0\r\n\r\n");
            await stream.WriteAsync(response, cancellationToken);
        }
    }

    private static async Task ServeTlsConnectionsAsync(
        TcpListener listener,
        X509Certificate2 certificate,
        int connectionCount,
        ConcurrentQueue<string> requestLines,
        CancellationToken cancellationToken)
    {
        for (var index = 0; index < connectionCount; index++)
        {
            using var client = await listener.AcceptTcpClientAsync(cancellationToken);
            using var tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
            try
            {
                await tls.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions
                    {
                        ServerCertificate = certificate,
                        EnabledSslProtocols = SslProtocols.Tls12,
                        ClientCertificateRequired = false,
                        ApplicationProtocols = [SslApplicationProtocol.Http11],
                    },
                    cancellationToken);
            }
            catch (AuthenticationException)
            {
                continue;
            }

            using var readCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            readCancellation.CancelAfter(TimeSpan.FromMilliseconds(500));
            try
            {
                var request = await ReadRequestHeadersAsync(tls, readCancellation.Token);
                if (request.Length > 0)
                {
                    requestLines.Enqueue(FirstLine(request));
                    var response = Encoding.ASCII.GetBytes(
                        "HTTP/1.1 200 OK\r\nServer: Caddy/2.8.4\r\nAllow: HEAD, OPTIONS\r\nContent-Length: 0\r\n\r\n");
                    await tls.WriteAsync(response, cancellationToken);
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // TLS posture connections intentionally complete no HTTP request.
            }
            catch (IOException)
            {
                // The client closes TLS posture connections immediately after authentication.
            }
        }
    }

    private static async Task ServeAdaptiveHttpsConnectionsAsync(
        TcpListener listener,
        X509Certificate2 certificate,
        TaskCompletionSource<byte[]> firstConnectionBytes,
        ConcurrentQueue<string> clearRequestLines,
        ConcurrentQueue<string> tlsRequestLines,
        CancellationToken cancellationToken)
    {
        using (var greetingClient = await listener.AcceptTcpClientAsync(cancellationToken))
        {
            firstConnectionBytes.SetResult(await ReadUntilPeerClosesAsync(
                greetingClient.GetStream(),
                cancellationToken));
        }

        using (var clearHttpClient = await listener.AcceptTcpClientAsync(cancellationToken))
        {
            var request = await ReadRequestHeadersAsync(
                clearHttpClient.GetStream(),
                cancellationToken);
            clearRequestLines.Enqueue(FirstLine(request));
        }

        using var tlsClient = await listener.AcceptTcpClientAsync(cancellationToken);
        using var tls = new SslStream(tlsClient.GetStream(), leaveInnerStreamOpen: false);
        await tls.AuthenticateAsServerAsync(
            new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                EnabledSslProtocols = SslProtocols.Tls12,
                ClientCertificateRequired = false,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
            },
            cancellationToken);
        var tlsRequest = await ReadRequestHeadersAsync(tls, cancellationToken);
        tlsRequestLines.Enqueue(FirstLine(tlsRequest));
        await tls.WriteAsync(
            Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nServer: Caddy/2.8.4\r\nContent-Length: 0\r\n\r\n"),
            cancellationToken);
    }

    private static async Task<byte[]> ReadUntilPeerClosesAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[1_024];
        while (output.Length < 8_192)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }

    private static async Task<string> ReadRequestHeadersAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var one = new byte[1];
        while (output.Length < 8_192)
        {
            var read = await stream.ReadAsync(one, cancellationToken);
            if (read == 0)
            {
                break;
            }

            output.WriteByte(one[0]);
            if (output.Length >= 4)
            {
                var data = output.GetBuffer();
                var length = checked((int)output.Length);
                if (data[length - 4] == '\r'
                    && data[length - 3] == '\n'
                    && data[length - 2] == '\r'
                    && data[length - 1] == '\n')
                {
                    break;
                }
            }
        }

        return Encoding.ASCII.GetString(output.ToArray());
    }

    private static string FirstLine(string request)
    {
        var separator = request.IndexOf("\r\n", StringComparison.Ordinal);
        return separator >= 0 ? request[..separator] : request;
    }

    private static X509Certificate2 CreateServerCertificate()
    {
        using var rsa = RSA.Create(2_048);
        var request = new CertificateRequest(
            "CN=localhost",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature,
            critical: false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1") },
            critical: false));
        using var generated = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(1));
        var pfx = generated.Export(X509ContentType.Pfx);
        try
        {
            return X509CertificateLoader.LoadPkcs12(
                pfx,
                password: null,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pfx);
        }
    }

    private sealed class RecordingDnsResolver(params IPAddress[] addresses) : IRemoteDnsResolver
    {
        private int callCount;

        public int CallCount => Volatile.Read(ref callCount);

        public string? LastTarget { get; private set; }

        public Task<IPAddress[]> ResolveAsync(string target, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref callCount);
            LastTarget = target;
            return Task.FromResult(addresses.ToArray());
        }
    }

    private sealed class RecordingRateLimiter : IRemoteConnectionRateLimiter
    {
        private int waitCount;

        public int WaitCount => Volatile.Read(ref waitCount);

        public ValueTask WaitAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref waitCount);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class BlockingRateLimiter : IRemoteConnectionRateLimiter
    {
        private int waitCount;

        public int WaitCount => Volatile.Read(ref waitCount);

        public async ValueTask WaitAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref waitCount);
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
    }
}
