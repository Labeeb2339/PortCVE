using System.Net;
using System.Text;
using System.Text.Json;
using PortCVE.Remote.Advisories;

namespace PortCVE.Tests;

public sealed class RemoteAdvisoryClientTests
{
    private const string OpenSshCpe = "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*";

    [Fact]
    public async Task EnrichAsync_OfflineUnresolvedAndHeuristicInputsMakeNoRequests()
    {
        using var httpClient = new HttpClient(new RecordingHandler(static (_, _, _) =>
            throw new InvalidOperationException("HTTP must not be called.")));
        var client = Client(httpClient);

        var offline = await client.EnrichAsync(Request(explicitOnline: false), CancellationToken.None);
        var unresolved = await client.EnrichAsync(
            Request(cpe: null),
            CancellationToken.None);
        var heuristic = await client.EnrichAsync(
            Request(confidence: RemoteAdvisoryConfidence.Heuristic),
            CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.NotRequested, offline.Status);
        Assert.Equal(RemoteAdvisoryResult.OfflineNetworkMode, offline.NetworkMode);
        Assert.Equal(RemoteAdvisoryStatus.Unresolved, unresolved.Status);
        Assert.Equal("cpe_unresolved", Assert.Single(unresolved.Diagnostics).Code);
        Assert.Equal(RemoteAdvisoryStatus.Unresolved, heuristic.Status);
        Assert.Empty(offline.Matches);
        Assert.Empty(unresolved.Matches);
        Assert.Empty(heuristic.Matches);
    }

    [Fact]
    public async Task EnrichAsync_UsesEncodedCpeAndApiKeyThenReturnsDeterministicMatches()
    {
        var response = Page(
            0,
            2,
            "2026-08-09T08:10:00.000Z",
            Cve("CVE-2026-12345", "LOW", "https://vendor.example/z", "https://vendor.example/a"),
            Cve("CVE-2026-12346", "CRITICAL", "https://vendor.example/b", "https://vendor.example/a"));
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(response)));
        using var httpClient = new HttpClient(handler);
        var client = Client(httpClient);

        var result = await client.EnrichAsync(
            Request(apiKey: "test-key-not-a-secret"),
            CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Complete, result.Status);
        Assert.Equal(RemoteAdvisoryResult.ProviderName, result.Provider);
        Assert.Equal(RemoteAdvisoryResult.ExplicitOnlineNetworkMode, result.NetworkMode);
        Assert.Equal(DateTimeOffset.Parse("2026-08-09T08:10:00Z"), result.SourceTimestamp);
        Assert.Empty(result.Diagnostics);

        Assert.Equal(2, result.Matches.Count);
        var match = result.Matches[0];
        Assert.Equal("CVE-2026-12345", match.AdvisoryId);
        Assert.Equal("candidate", match.Classification);
        Assert.Equal("remote_banner_match", match.MatchMethod);
        Assert.Equal("not_assessed", match.Exploitability);
        Assert.Equal(
            RemoteAdvisoryApplicabilityDisposition.DirectCandidate,
            match.Applicability.Disposition);
        Assert.Equal(RemoteAdvisorySeverity.Low, match.Severity);
        Assert.Equal(
            ["https://vendor.example/a", "https://vendor.example/z"],
            match.References);
        Assert.Equal("CVE-2026-12346", result.Matches[1].AdvisoryId);
        Assert.Equal(RemoteAdvisorySeverity.Critical, result.Matches[1].Severity);
        Assert.Equal(
            ["https://vendor.example/a", "https://vendor.example/b"],
            result.Matches[1].References);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("services.nvd.nist.gov", request.Uri.Host);
        Assert.StartsWith("/rest/json/cves/2.0", request.Uri.AbsolutePath, StringComparison.Ordinal);
        Assert.Contains("cpeName=cpe%3A2.3%3Aa%3Aopenbsd%3Aopenssh%3A9.6%3Ap1", request.Uri.OriginalString, StringComparison.Ordinal);
        Assert.Contains("isVulnerable", request.Uri.Query, StringComparison.Ordinal);
        Assert.Contains("noRejected", request.Uri.Query, StringComparison.Ordinal);
        Assert.Equal(["test-key-not-a-secret"], request.Headers["apiKey"]);
    }

    [Fact]
    public async Task EnrichAsync_DuplicateCveWithConflictingApplicabilityFailsClosed()
    {
        var direct = Cve("CVE-2026-12345", "HIGH");
        var inconclusive = Cve("CVE-2026-12345", "HIGH");
        inconclusive["configurations"] = RangeConfigurations();
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 2, "2026-08-09T08:10:00.000Z", direct, inconclusive))));
        using var httpClient = new HttpClient(handler);
        var client = Client(httpClient);

        var result = await client.EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Failed, result.Status);
        Assert.Equal("nvd_duplicate_cve", Assert.Single(result.Diagnostics).Code);
        Assert.Empty(result.Matches);
        Assert.Null(result.SourceTimestamp);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task EnrichAsync_PaginatesWithinCapsAndEnforcesSpacing()
    {
        var responses = new Queue<string>(
        [
            Page(0, 2, "2026-08-09T08:10:00Z", Cve("CVE-2026-10001", "LOW")),
            Page(1, 2, "2026-08-09T08:10:06Z", Cve("CVE-2026-10002", "HIGH")),
        ]);
        var handler = new RecordingHandler((_, _, _) =>
            Task.FromResult(JsonResponse(responses.Dequeue())));
        var time = new ManualTime(new DateTimeOffset(2026, 8, 9, 8, 0, 0, TimeSpan.Zero));
        using var httpClient = new HttpClient(handler);
        var client = new NvdAdvisoryClient(
            httpClient,
            time,
            time,
            Options(resultsPerPage: 1, maxRequests: 2, maxCandidates: 2));

        var result = await client.EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Complete, result.Status);
        Assert.Equal(["CVE-2026-10001", "CVE-2026-10002"], result.Matches.Select(static match => match.AdvisoryId));
        Assert.Equal([TimeSpan.FromSeconds(6)], time.Delays);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains("startIndex=0", handler.Requests[0].Uri.Query, StringComparison.Ordinal);
        Assert.Contains("startIndex=1", handler.Requests[1].Uri.Query, StringComparison.Ordinal);
        Assert.Equal(DateTimeOffset.Parse("2026-08-09T08:10:06Z"), result.SourceTimestamp);
    }

    [Fact]
    public async Task EnrichAsync_ResultCapFailsClosedWithoutFetchingMorePages()
    {
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 3, "2026-08-09T08:10:00Z", Cve("CVE-2026-10001", "LOW")))));
        using var httpClient = new HttpClient(handler);
        var client = Client(
            httpClient,
            Options(resultsPerPage: 1, maxRequests: 2, maxCandidates: 2));

        var result = await client.EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Failed, result.Status);
        Assert.Equal("nvd_result_cap_exceeded", Assert.Single(result.Diagnostics).Code);
        Assert.Empty(result.Matches);
        Assert.Single(handler.Requests);
        Assert.Null(result.SourceTimestamp);
    }

    [Fact]
    public async Task EnrichAsync_MalformedLaterRecordFailsClosedAndDiscardsEarlierRecord()
    {
        var valid = Cve("CVE-2026-10001", "LOW");
        var malformed = Cve("CVE-2026-10002", "HIGH");
        _ = malformed.Remove("references");
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 2, "2026-08-09T08:10:00Z", valid, malformed))));
        using var httpClient = new HttpClient(handler);

        var result = await Client(httpClient)
            .EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Failed, result.Status);
        Assert.Equal("nvd_schema_invalid", Assert.Single(result.Diagnostics).Code);
        Assert.Empty(result.Matches);
        Assert.Null(result.SourceTimestamp);
    }

    [Fact]
    public async Task EnrichAsync_OversizedResponseFailsClosed()
    {
        var oversized = new string('x', 2048);
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(oversized)));
        using var httpClient = new HttpClient(handler);
        var client = Client(httpClient, Options(maxResponseBytes: 1024));

        var result = await client.EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Failed, result.Status);
        Assert.Equal("nvd_response_too_large", Assert.Single(result.Diagnostics).Code);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task EnrichAsync_RequestTimeoutReturnsUnavailableWithoutMatches()
    {
        var handler = new RecordingHandler(async (_, _, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("Unreachable");
        });
        using var httpClient = new HttpClient(handler);
        var options = Options() with { RequestTimeout = TimeSpan.FromMilliseconds(50) };
        var client = Client(httpClient, options);

        var result = await client.EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Unavailable, result.Status);
        Assert.Equal("nvd_timeout", Assert.Single(result.Diagnostics).Code);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task EnrichAsync_CallerCancellationPropagates()
    {
        var handler = new RecordingHandler(static (_, _, _) =>
            throw new InvalidOperationException("HTTP must not be called."));
        using var httpClient = new HttpClient(handler);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Client(httpClient).EnrichAsync(Request(), cancellation.Token));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task EnrichAsync_RateLimitResponseIsUnavailableAndDoesNotParseBody()
    {
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.TooManyRequests)
            {
                Content = new StringContent("not-json", Encoding.UTF8, "text/plain"),
            }));
        using var httpClient = new HttpClient(handler);

        var result = await Client(httpClient)
            .EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Unavailable, result.Status);
        Assert.Equal("nvd_rate_limited", Assert.Single(result.Diagnostics).Code);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task EnrichAsync_CompoundApplicabilityIsConditionalAndPreserved()
    {
        var cve = Cve("CVE-2026-20001", "HIGH");
        cve["configurations"] = CompoundConfigurations(negate: false);
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 1, "2026-08-09T08:10:00Z", cve))));
        using var httpClient = new HttpClient(handler);

        var result = await Client(httpClient).EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Complete, result.Status);
        var match = Assert.Single(result.Matches);
        Assert.Equal("conditional_candidate", match.Classification);
        Assert.Equal(
            RemoteAdvisoryApplicabilityDisposition.ConditionalCandidate,
            match.Applicability.Disposition);
        Assert.True(match.Applicability.QueriedCpeVulnerableLeafFound);
        Assert.True(match.Applicability.HasRequiredCofactors);
        var node = Assert.Single(Assert.Single(match.Applicability.Configurations).Nodes);
        Assert.Equal("AND", node.Operator);
        Assert.Equal(2, node.CpeMatches.Count);
        Assert.Contains(node.CpeMatches, static criterion =>
            criterion.MatchesQueriedIdentity && criterion.Vulnerable);
        Assert.Contains(node.CpeMatches, static criterion => !criterion.Vulnerable);
        Assert.Equal("not_assessed", match.Exploitability);
    }

    [Fact]
    public async Task EnrichAsync_WrongVersionDirectBranchCannotOverrideTrueConditionalBranch()
    {
        var cve = Cve("CVE-2026-20006", "HIGH");
        cve["configurations"] = WrongVersionAndConditionalConfigurations();
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 1, "2026-08-09T08:10:00Z", cve))));
        using var httpClient = new HttpClient(handler);

        var match = Assert.Single((await Client(httpClient)
            .EnrichAsync(Request(), CancellationToken.None)).Matches);

        Assert.Equal("conditional_candidate", match.Classification);
        Assert.Equal(
            RemoteAdvisoryApplicabilityDisposition.ConditionalCandidate,
            match.Applicability.Disposition);
        var wrongVersion = match.Applicability.Configurations[0].Nodes[0].CpeMatches[0];
        Assert.Equal(RemoteAdvisoryCpeAlignment.NoMatch, wrongVersion.IdentityAlignment);
        Assert.False(wrongVersion.MatchesQueriedIdentity);
        var queriedVersion = match.Applicability.Configurations[1].Nodes[0].CpeMatches[0];
        Assert.Equal(RemoteAdvisoryCpeAlignment.Proven, queriedVersion.IdentityAlignment);
        Assert.True(queriedVersion.MatchesQueriedIdentity);
    }

    [Fact]
    public async Task EnrichAsync_UnobservedCpeQualifierCannotBecomeDirectCandidate()
    {
        var cve = Cve("CVE-2026-20007", "HIGH");
        cve["configurations"] = QualifiedConfigurations();
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 1, "2026-08-09T08:10:00Z", cve))));
        using var httpClient = new HttpClient(handler);

        var match = Assert.Single((await Client(httpClient)
            .EnrichAsync(Request(), CancellationToken.None)).Matches);

        Assert.Equal("conditional_candidate", match.Classification);
        Assert.False(match.Applicability.QueriedCpeVulnerableLeafFound);
        Assert.True(match.Applicability.HasRequiredCofactors);
        var criterion = Assert.Single(
            Assert.Single(Assert.Single(match.Applicability.Configurations).Nodes).CpeMatches);
        Assert.Equal(
            RemoteAdvisoryCpeAlignment.ConditionalOnUnobservedQualifier,
            criterion.IdentityAlignment);
        Assert.False(criterion.MatchesQueriedIdentity);
        Assert.True(criterion.HasUnobservedQualifiers);
    }

    [Fact]
    public async Task EnrichAsync_VersionRangeIsInconclusiveWithoutMatchCriteriaExpansion()
    {
        var cve = Cve("CVE-2026-20008", "HIGH");
        cve["configurations"] = RangeConfigurations();
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 1, "2026-08-09T08:10:00Z", cve))));
        using var httpClient = new HttpClient(handler);

        var match = Assert.Single((await Client(httpClient)
            .EnrichAsync(Request(), CancellationToken.None)).Matches);

        Assert.Equal("inconclusive", match.Classification);
        Assert.Equal(
            RemoteAdvisoryApplicabilityDisposition.Inconclusive,
            match.Applicability.Disposition);
        var criterion = Assert.Single(
            Assert.Single(Assert.Single(match.Applicability.Configurations).Nodes).CpeMatches);
        Assert.Equal(
            RemoteAdvisoryCpeAlignment.InconclusiveConstraint,
            criterion.IdentityAlignment);
        Assert.False(criterion.MatchesQueriedIdentity);
        Assert.Contains(match.Applicability.Limitations, limitation =>
            limitation.Contains("range", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task EnrichAsync_DirectAlternativeWinsWithoutReportingRequiredCofactors()
    {
        var cve = Cve("CVE-2026-20009", "HIGH");
        cve["configurations"] = DirectConfigurations()
            .Concat(CompoundConfigurations(negate: false))
            .ToArray();
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 1, "2026-08-09T08:10:00Z", cve))));
        using var httpClient = new HttpClient(handler);

        var match = Assert.Single((await Client(httpClient)
            .EnrichAsync(Request(), CancellationToken.None)).Matches);

        Assert.Equal("candidate", match.Classification);
        Assert.False(match.Applicability.HasRequiredCofactors);
    }

    [Fact]
    public async Task EnrichAsync_NegatedApplicabilityIsInconclusive()
    {
        var cve = Cve("CVE-2026-20002", "HIGH");
        cve["configurations"] = CompoundConfigurations(negate: true);
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 1, "2026-08-09T08:10:00Z", cve))));
        using var httpClient = new HttpClient(handler);

        var match = Assert.Single((await Client(httpClient)
            .EnrichAsync(Request(), CancellationToken.None)).Matches);

        Assert.Equal("inconclusive", match.Classification);
        Assert.Equal(
            RemoteAdvisoryApplicabilityDisposition.Inconclusive,
            match.Applicability.Disposition);
        Assert.Contains(match.Applicability.Limitations, limitation =>
            limitation.Contains("negation", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task EnrichAsync_AnalyzedRecordWithoutConfigurationsFailsClosed()
    {
        var cve = Cve("CVE-2026-20003", "HIGH");
        _ = cve.Remove("configurations");
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 1, "2026-08-09T08:10:00Z", cve))));
        using var httpClient = new HttpClient(handler);

        var result = await Client(httpClient).EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Failed, result.Status);
        Assert.Equal("nvd_schema_invalid", Assert.Single(result.Diagnostics).Code);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task EnrichAsync_ModifiedRecordIsRetainedAsPartialWithStatus()
    {
        var cve = Cve("CVE-2026-20004", "HIGH");
        cve["vulnStatus"] = "Modified";
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 1, "2026-08-09T08:10:00Z", cve))));
        using var httpClient = new HttpClient(handler);

        var result = await Client(httpClient).EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Partial, result.Status);
        var match = Assert.Single(result.Matches);
        Assert.Equal("Modified", match.NvdStatus);
        Assert.Equal(DateTimeOffset.Parse("2026-08-02T00:00:00Z"), match.NvdLastModified);
        Assert.Equal("nvd_enrichment_modified", Assert.Single(result.Diagnostics).Code);
    }

    [Fact]
    public async Task EnrichAsync_AwaitingAnalysisIsPartialAndEmitsNoMatch()
    {
        var cve = Cve("CVE-2026-20005", "HIGH");
        cve["vulnStatus"] = "Awaiting Analysis";
        _ = cve.Remove("configurations");
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 1, "2026-08-09T08:10:00Z", cve))));
        using var httpClient = new HttpClient(handler);

        var result = await Client(httpClient).EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Partial, result.Status);
        Assert.Empty(result.Matches);
        Assert.Equal("nvd_enrichment_incomplete", Assert.Single(result.Diagnostics).Code);
    }

    [Fact]
    public async Task EnrichAsync_CatalogResolutionIdentityMismatchMakesNoRequest()
    {
        var handler = new RecordingHandler(static (_, _, _) =>
            throw new InvalidOperationException("HTTP must not be called."));
        using var httpClient = new HttpClient(handler);
        var resolution = new RemoteBannerCpeCatalog().Resolve(
            "OpenSSH",
            "9.6p1",
            "SSH-2.0-OpenSSH_9.6p1",
            RemoteAdvisoryConfidence.Strong);
        var mismatched = new RemoteAdvisoryRequest(
            new(
                "Apache HTTP Server",
                "9.6p1",
                "SSH-2.0-OpenSSH_9.6p1",
                RemoteAdvisoryConfidence.Strong,
                resolution),
            ExplicitOnline: true);

        var result = await Client(httpClient).EnrichAsync(mismatched, CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Unresolved, result.Status);
        Assert.Equal("cpe_identity_binding_mismatch", Assert.Single(result.Diagnostics).Code);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task EnrichAsync_ProcessLimiterSpacesRequestsAcrossClientInstances()
    {
        var handler = new RecordingHandler((_, _, _) => Task.FromResult(JsonResponse(
            Page(0, 0, "2026-08-09T08:10:00Z"))));
        var time = new ManualTime(new DateTimeOffset(2026, 8, 9, 8, 0, 0, TimeSpan.Zero));
        var limiter = new NvdProcessRateLimiter(time, time);
        using var httpClient = new HttpClient(handler);
        var firstClient = new NvdAdvisoryClient(httpClient, time, time, Options(), limiter);
        var secondClient = new NvdAdvisoryClient(httpClient, time, time, Options(), limiter);

        _ = await firstClient.EnrichAsync(Request(), CancellationToken.None);
        _ = await secondClient.EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal([NvdProcessRateLimiter.ProductionMinimumSpacing], time.Delays);
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task EnrichAsync_RetryAfterDelaysNextProcessRequest(
        HttpStatusCode statusCode)
    {
        var handler = new RecordingHandler((_, requestNumber, _) =>
        {
            if (requestNumber == 0)
            {
                var response = new HttpResponseMessage(statusCode);
                response.Headers.RetryAfter = new(TimeSpan.FromSeconds(20));
                return Task.FromResult(response);
            }

            return Task.FromResult(JsonResponse(Page(0, 0, "2026-08-09T08:10:20Z")));
        });
        var time = new ManualTime(new DateTimeOffset(2026, 8, 9, 8, 0, 0, TimeSpan.Zero));
        var limiter = new NvdProcessRateLimiter(time, time);
        using var httpClient = new HttpClient(handler);
        var firstClient = new NvdAdvisoryClient(httpClient, time, time, Options(), limiter);
        var secondClient = new NvdAdvisoryClient(httpClient, time, time, Options(), limiter);

        var limited = await firstClient.EnrichAsync(Request(), CancellationToken.None);
        var recovered = await secondClient.EnrichAsync(Request(), CancellationToken.None);

        Assert.Equal(RemoteAdvisoryStatus.Unavailable, limited.Status);
        Assert.Equal(RemoteAdvisoryStatus.Complete, recovered.Status);
        Assert.Equal([TimeSpan.FromSeconds(20)], time.Delays);
    }

    [Fact]
    public async Task RateLimiter_RetryAfterExtendsAnAlreadyWaitingRequest()
    {
        var time = new BlockingTime(
            new DateTimeOffset(2026, 8, 9, 8, 0, 0, TimeSpan.Zero));
        var limiter = new NvdProcessRateLimiter(time, time);
        await limiter.WaitAsync(CancellationToken.None);

        var waitingRequest = limiter.WaitAsync(CancellationToken.None);
        await time.FirstDelayStarted.WaitAsync(TimeSpan.FromSeconds(2));
        await limiter.ApplyRetryAfterAsync(TimeSpan.FromSeconds(20), CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(2));
        time.ReleaseFirstDelay();
        await waitingRequest.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal([TimeSpan.FromSeconds(6), TimeSpan.FromSeconds(14)], time.Delays);
    }

    private static RemoteAdvisoryRequest Request(
        bool explicitOnline = true,
        string? cpe = OpenSshCpe,
        RemoteAdvisoryConfidence confidence = RemoteAdvisoryConfidence.Strong,
        string? apiKey = null)
    {
        var resolution = cpe is null
            ? null
            : new RemoteBannerCpeCatalog().Resolve(
                "OpenSSH",
                "9.6p1",
                "SSH-2.0-OpenSSH_9.6p1",
                confidence);
        return new(
            new(
                "OpenSSH",
                "9.6p1",
                "SSH-2.0-OpenSSH_9.6p1",
                confidence,
                resolution),
            explicitOnline,
            apiKey);
    }

    private static NvdAdvisoryClient Client(
        HttpClient httpClient,
        NvdAdvisoryClientOptions? options = null)
    {
        var time = new ManualTime(new DateTimeOffset(2026, 8, 9, 8, 0, 0, TimeSpan.Zero));
        return new(httpClient, time, time, options);
    }

    private static NvdAdvisoryClientOptions Options(
        int resultsPerPage = 10,
        int maxRequests = 2,
        int maxCandidates = 20,
        int maxResponseBytes = 64 * 1024) =>
        new(
            resultsPerPage,
            maxRequests,
            maxCandidates,
            maxResponseBytes,
            MaxReferencesPerAdvisory: 20,
            RequestTimeout: TimeSpan.FromSeconds(5));

    private static Dictionary<string, object?> Cve(
        string id,
        string severity,
        params string[] references) =>
        new(StringComparer.Ordinal)
        {
            ["id"] = id,
            ["sourceIdentifier"] = "security@example.test",
            ["published"] = "2026-08-01T00:00:00.000Z",
            ["lastModified"] = "2026-08-02T00:00:00.000Z",
            ["vulnStatus"] = "Analyzed",
            ["descriptions"] = new[]
            {
                new { lang = "en", value = $"Description for {id}." },
            },
            ["metrics"] = new
            {
                cvssMetricV31 = new[]
                {
                    new
                    {
                        source = "nvd@nist.gov",
                        type = "Primary",
                        cvssData = new
                        {
                            version = "3.1",
                            vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            baseScore = severity == "CRITICAL" ? 9.8 : severity == "HIGH" ? 8.1 : 3.1,
                            baseSeverity = severity,
                        },
                    },
                },
            },
            ["configurations"] = DirectConfigurations(),
            ["references"] = (references.Length == 0
                ? new[] { "https://nvd.nist.gov/vuln/detail/" + id }
                : references)
                .Select(static url => new { url })
                .ToArray(),
        };

    private static object[] DirectConfigurations() =>
    [
        new
        {
            nodes = new[]
            {
                new
                {
                    @operator = "OR",
                    negate = false,
                    cpeMatch = new[]
                    {
                        new
                        {
                            vulnerable = true,
                            criteria = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                            matchCriteriaId = "c6d7d468-c829-4a4e-8865-e62d8ec5e274",
                        },
                    },
                },
            },
        },
    ];

    private static object[] CompoundConfigurations(bool negate) =>
    [
        new
        {
            nodes = new[]
            {
                new
                {
                    @operator = "AND",
                    negate,
                    cpeMatch = new object[]
                    {
                        new
                        {
                            vulnerable = true,
                            criteria = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                            matchCriteriaId = "c6d7d468-c829-4a4e-8865-e62d8ec5e274",
                        },
                        new
                        {
                            vulnerable = false,
                            criteria = "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*",
                            matchCriteriaId = "11111111-2222-3333-4444-555555555555",
                        },
                    },
                },
            },
        },
    ];

    private static object[] WrongVersionAndConditionalConfigurations() =>
    [
        new
        {
            nodes = new[]
            {
                new
                {
                    @operator = "OR",
                    negate = false,
                    cpeMatch = new[]
                    {
                        new
                        {
                            vulnerable = true,
                            criteria = "cpe:2.3:a:openbsd:openssh:9.9:p1:*:*:*:*:*:*",
                            matchCriteriaId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                        },
                    },
                },
            },
        },
        new
        {
            nodes = new[]
            {
                new
                {
                    @operator = "AND",
                    negate = false,
                    cpeMatch = new object[]
                    {
                        new
                        {
                            vulnerable = true,
                            criteria = OpenSshCpe,
                            matchCriteriaId = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
                        },
                        new
                        {
                            vulnerable = false,
                            criteria = "cpe:2.3:o:redhat:enterprise_linux:9:*:*:*:*:*:*:*",
                            matchCriteriaId = "cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa",
                        },
                    },
                },
            },
        },
    ];

    private static object[] QualifiedConfigurations() =>
    [
        new
        {
            nodes = new[]
            {
                new
                {
                    @operator = "OR",
                    negate = false,
                    cpeMatch = new[]
                    {
                        new
                        {
                            vulnerable = true,
                            criteria = "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:windows:*:*",
                            matchCriteriaId = "dddddddd-eeee-ffff-aaaa-bbbbbbbbbbbb",
                        },
                    },
                },
            },
        },
    ];

    private static object[] RangeConfigurations() =>
    [
        new
        {
            nodes = new[]
            {
                new
                {
                    @operator = "OR",
                    negate = false,
                    cpeMatch = new[]
                    {
                        new
                        {
                            vulnerable = true,
                            criteria = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                            matchCriteriaId = "eeeeeeee-ffff-aaaa-bbbb-cccccccccccc",
                            versionStartIncluding = "10.0",
                        },
                    },
                },
            },
        },
    ];

    private static string Page(
        int startIndex,
        int totalResults,
        string timestamp,
        params Dictionary<string, object?>[] cves) =>
        JsonSerializer.Serialize(new
        {
            resultsPerPage = cves.Length,
            startIndex,
            totalResults,
            format = "NVD_CVE",
            version = "2.0",
            timestamp,
            vulnerabilities = cves.Select(static cve => new { cve }).ToArray(),
        });

    private static HttpResponseMessage JsonResponse(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };

    private sealed class RecordingHandler(
        Func<HttpRequestMessage, int, CancellationToken, Task<HttpResponseMessage>> responder)
        : HttpMessageHandler
    {
        private int _requestNumber;

        internal List<RecordedRequest> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var requestNumber = _requestNumber++;
            Requests.Add(new(
                request.Method,
                request.RequestUri!,
                request.Headers.ToDictionary(
                    static header => header.Key,
                    static header => header.Value.ToArray(),
                    StringComparer.OrdinalIgnoreCase)));
            return responder(request, requestNumber, cancellationToken);
        }
    }

    private sealed record RecordedRequest(
        HttpMethod Method,
        Uri Uri,
        IReadOnlyDictionary<string, string[]> Headers);

    private sealed class ManualTime(DateTimeOffset utcNow) :
        IRemoteAdvisoryClock,
        IRemoteAdvisoryDelay
    {
        public DateTimeOffset UtcNow { get; private set; } = utcNow;

        public TimeSpan MonotonicNow { get; private set; }

        internal List<TimeSpan> Delays { get; } = [];

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Delays.Add(delay);
            UtcNow += delay;
            MonotonicNow += delay;
            return Task.CompletedTask;
        }
    }

    private sealed class BlockingTime(DateTimeOffset initialUtcNow) :
        IRemoteAdvisoryClock,
        IRemoteAdvisoryDelay
    {
        private readonly Lock _sync = new();
        private readonly TaskCompletionSource<bool> _firstDelayStarted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> _releaseFirstDelay =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly List<TimeSpan> _delays = [];
        private long _elapsedTicks;
        private int _delayCount;

        public DateTimeOffset UtcNow =>
            initialUtcNow + TimeSpan.FromTicks(Interlocked.Read(ref _elapsedTicks));

        public TimeSpan MonotonicNow =>
            TimeSpan.FromTicks(Interlocked.Read(ref _elapsedTicks));

        internal Task FirstDelayStarted => _firstDelayStarted.Task;

        internal IReadOnlyList<TimeSpan> Delays
        {
            get
            {
                lock (_sync)
                {
                    return _delays.ToArray();
                }
            }
        }

        public async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            int delayNumber;
            lock (_sync)
            {
                _delays.Add(delay);
                delayNumber = ++_delayCount;
            }

            if (delayNumber == 1)
            {
                _firstDelayStarted.TrySetResult(true);
                await _releaseFirstDelay.Task.WaitAsync(cancellationToken);
            }

            _ = Interlocked.Add(ref _elapsedTicks, delay.Ticks);
        }

        internal void ReleaseFirstDelay() => _releaseFirstDelay.TrySetResult(true);
    }
}
