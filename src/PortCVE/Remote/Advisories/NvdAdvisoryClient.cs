using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PortCVE.Remote.Advisories;

internal sealed partial class NvdAdvisoryClient : IRemoteAdvisoryClient
{
    private static readonly Uri Endpoint =
        new("https://services.nvd.nist.gov/rest/json/cves/2.0");

    private readonly HttpClient _httpClient;
    private readonly IRemoteAdvisoryClock _clock;
    private readonly INvdRequestRateLimiter _rateLimiter;
    private readonly NvdAdvisoryClientOptions _options;

    internal NvdAdvisoryClient(
        HttpClient httpClient,
        IRemoteAdvisoryClock? clock = null,
        IRemoteAdvisoryDelay? delay = null,
        NvdAdvisoryClientOptions? options = null,
        INvdRequestRateLimiter? rateLimiter = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _clock = clock ?? SystemRemoteAdvisoryClock.Instance;
        var resolvedDelay = delay ?? SystemRemoteAdvisoryDelay.Instance;
        _rateLimiter = rateLimiter ??
            (clock is null && delay is null
                ? NvdProcessRateLimiter.Shared
                : new NvdProcessRateLimiter(_clock, resolvedDelay));
        _options = options ?? NvdAdvisoryClientOptions.Default;
        _options.Validate();
    }

    public async Task<RemoteAdvisoryResult> EnrichAsync(
        RemoteAdvisoryRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!request.ExplicitOnline)
        {
            return Result(
                RemoteAdvisoryStatus.NotRequested,
                RemoteAdvisoryResult.OfflineNetworkMode,
                "online_not_explicit",
                "NVD enrichment was not requested explicitly.");
        }

        var validation = ValidateRequest(request);
        if (validation is not null)
        {
            return Result(
                validation.Status,
                RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
                validation.Code,
                validation.Message);
        }

        return await FetchAllAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task<RemoteAdvisoryResult> FetchAllAsync(
        RemoteAdvisoryRequest request,
        CancellationToken cancellationToken)
    {
        var cpe23Uri = request.Identity.CpeResolution!.Cpe23Uri!;
        var parsed = new List<ParsedAdvisory>();
        var timestamps = new List<DateTimeOffset>();
        int? expectedTotal = null;
        var startIndex = 0;

        for (var requestNumber = 0; requestNumber < _options.MaxRequests; requestNumber++)
        {
            await _rateLimiter.WaitAsync(cancellationToken).ConfigureAwait(false);

            ParsedPage page;
            try
            {
                page = await FetchPageAsync(
                    cpe23Uri,
                    request.NvdApiKey,
                    startIndex,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return Result(
                    RemoteAdvisoryStatus.Unavailable,
                    RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
                    "nvd_timeout",
                    "The NVD request exceeded the configured timeout.");
            }
            catch (NvdResponseException exception)
            {
                return Result(
                    exception.Status,
                    RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
                    exception.Code,
                    exception.Message);
            }
            catch (HttpRequestException)
            {
                return Result(
                    RemoteAdvisoryStatus.Unavailable,
                    RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
                    "nvd_transport_failed",
                    "The NVD API request failed before a complete response was received.");
            }
            catch (IOException)
            {
                return Result(
                    RemoteAdvisoryStatus.Failed,
                    RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
                    "nvd_response_incomplete",
                    "The NVD API response ended before it could be validated.");
            }
            catch (JsonException)
            {
                return Result(
                    RemoteAdvisoryStatus.Failed,
                    RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
                    "nvd_schema_invalid",
                    "The NVD API response was not valid CVE API 2.0 JSON.");
            }

            expectedTotal ??= page.TotalResults;
            if (page.TotalResults != expectedTotal.Value)
            {
                return Result(
                    RemoteAdvisoryStatus.Failed,
                    RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
                    "nvd_pagination_changed",
                    "The NVD result set changed during pagination; no partial matches were retained.");
            }

            if (page.TotalResults > _options.MaxCandidates)
            {
                return Result(
                    RemoteAdvisoryStatus.Failed,
                    RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
                    "nvd_result_cap_exceeded",
                    $"The NVD result set exceeded the {_options.MaxCandidates.ToString(CultureInfo.InvariantCulture)}-record safety cap.");
            }

            parsed.AddRange(page.Advisories);
            timestamps.Add(page.Timestamp);
            startIndex += page.ResultCount;

            if (parsed
                .GroupBy(static advisory => advisory.AdvisoryId, StringComparer.OrdinalIgnoreCase)
                .Any(static group => group.Skip(1).Any()))
            {
                return Result(
                    RemoteAdvisoryStatus.Failed,
                    RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
                    "nvd_duplicate_cve",
                    "The NVD response contained a duplicate CVE identifier; no matches were retained.");
            }

            if (startIndex == page.TotalResults)
            {
                var matches = CreateMatches(
                    parsed.Where(static advisory => advisory.EmitMatch).ToArray(),
                    request.Identity,
                    cpe23Uri);
                var incomplete = parsed
                    .Where(static advisory => !string.Equals(
                        advisory.NvdStatus,
                        "Analyzed",
                        StringComparison.Ordinal))
                    .OrderBy(static advisory => advisory.AdvisoryId, StringComparer.Ordinal)
                    .ToArray();
                var diagnostics = incomplete
                    .Select(static advisory => new RemoteAdvisoryDiagnostic(
                        advisory.EmitMatch
                            ? "nvd_enrichment_modified"
                            : "nvd_enrichment_incomplete",
                        $"{advisory.AdvisoryId} has NVD status {advisory.NvdStatus}; enrichment is not complete."))
                    .ToArray();
                return new(
                    incomplete.Length == 0
                        ? RemoteAdvisoryStatus.Complete
                        : RemoteAdvisoryStatus.Partial,
                    RemoteAdvisoryResult.ProviderName,
                    RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
                    timestamps.Count == 0 ? null : timestamps.Max(),
                    matches,
                    diagnostics);
            }

            if (page.ResultCount == 0 || startIndex > page.TotalResults)
            {
                return Result(
                    RemoteAdvisoryStatus.Failed,
                    RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
                    "nvd_pagination_invalid",
                    "The NVD pagination metadata was inconsistent; no partial matches were retained.");
            }
        }

        return Result(
            RemoteAdvisoryStatus.Failed,
            RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
            "nvd_request_cap_exceeded",
            $"The NVD query required more than {_options.MaxRequests.ToString(CultureInfo.InvariantCulture)} requests; no partial matches were retained.");
    }

    private async Task<ParsedPage> FetchPageAsync(
        string cpe23Uri,
        string? apiKey,
        int startIndex,
        CancellationToken cancellationToken)
    {
        var uri = new Uri(
            $"{Endpoint}?cpeName={Uri.EscapeDataString(cpe23Uri)}" +
            $"&isVulnerable&noRejected&resultsPerPage={_options.ResultsPerPage.ToString(CultureInfo.InvariantCulture)}" +
            $"&startIndex={startIndex.ToString(CultureInfo.InvariantCulture)}");

        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("PortCVE/remote-advisory-enrichment");
        if (!string.IsNullOrEmpty(apiKey))
        {
            _ = request.Headers.TryAddWithoutValidation("apiKey", apiKey);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.RequestTimeout);
        using var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            timeout.Token).ConfigureAwait(false);

        if (response.RequestMessage?.RequestUri is { } responseUri &&
            !IsExpectedNvdEndpoint(responseUri))
        {
            throw new NvdResponseException(
                RemoteAdvisoryStatus.Failed,
                "nvd_endpoint_mismatch",
                "The HTTP response did not originate from the configured NVD CVE API 2.0 endpoint.");
        }

        if (!response.IsSuccessStatusCode)
        {
            if (response.StatusCode == HttpStatusCode.TooManyRequests ||
                response.Headers.RetryAfter is not null)
            {
                await _rateLimiter.ApplyRetryAfterAsync(
                    GetRetryAfter(response),
                    CancellationToken.None).ConfigureAwait(false);
            }

            var unavailable = response.StatusCode is HttpStatusCode.TooManyRequests or
                HttpStatusCode.ServiceUnavailable or
                HttpStatusCode.BadGateway or
                HttpStatusCode.GatewayTimeout ||
                (int)response.StatusCode >= 500;
            throw new NvdResponseException(
                unavailable ? RemoteAdvisoryStatus.Unavailable : RemoteAdvisoryStatus.Failed,
                response.StatusCode == HttpStatusCode.TooManyRequests
                    ? "nvd_rate_limited"
                    : "nvd_http_error",
                unavailable
                    ? "The NVD API is temporarily unavailable or rate-limited."
                    : "The NVD API rejected the request.");
        }

        var bytes = await ReadBoundedAsync(response.Content, timeout.Token).ConfigureAwait(false);
        return ParsePage(bytes, startIndex, cpe23Uri);
    }

    private static bool IsExpectedNvdEndpoint(Uri? uri) =>
        uri is not null &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(uri.Host, Endpoint.Host, StringComparison.OrdinalIgnoreCase) &&
        uri.IsDefaultPort &&
        string.Equals(uri.AbsolutePath, Endpoint.AbsolutePath, StringComparison.Ordinal);

    private TimeSpan GetRetryAfter(HttpResponseMessage response)
    {
        var retryAfter = response.Headers.RetryAfter?.Delta;
        if (retryAfter is null && response.Headers.RetryAfter?.Date is { } retryDate)
        {
            retryAfter = retryDate - _clock.UtcNow;
        }

        return retryAfter.HasValue && retryAfter.Value > TimeSpan.Zero
            ? retryAfter.Value
            : TimeSpan.FromSeconds(30);
    }

    private async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > 0 &&
            content.Headers.ContentLength > _options.MaxResponseBytes)
        {
            throw new NvdResponseException(
                RemoteAdvisoryStatus.Failed,
                "nvd_response_too_large",
                "The NVD API response exceeded the configured byte cap.");
        }

        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = ArrayPool<byte>.Shared.Rent(16 * 1024);
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    return output.ToArray();
                }

                if (output.Length + read > _options.MaxResponseBytes)
                {
                    throw new NvdResponseException(
                        RemoteAdvisoryStatus.Failed,
                        "nvd_response_too_large",
                        "The NVD API response exceeded the configured byte cap.");
                }

                output.Write(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private ParsedPage ParsePage(
        ReadOnlyMemory<byte> bytes,
        int expectedStartIndex,
        string queriedCpe23Uri)
    {
        using var document = JsonDocument.Parse(
            bytes,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64,
            });
        var root = RequireObject(document.RootElement, "root");

        var format = RequireString(root, "format");
        var version = RequireString(root, "version");
        if (!string.Equals(format, "NVD_CVE", StringComparison.Ordinal) ||
            !string.Equals(version, "2.0", StringComparison.Ordinal))
        {
            throw SchemaInvalid("The response did not identify itself as NVD CVE API 2.0 data.");
        }

        var startIndex = RequireNonNegativeInt(root, "startIndex");
        var resultsPerPage = RequireNonNegativeInt(root, "resultsPerPage");
        var totalResults = RequireNonNegativeInt(root, "totalResults");
        if (startIndex != expectedStartIndex)
        {
            throw SchemaInvalid("The response startIndex did not match the requested page.");
        }

        var timestampText = RequireString(root, "timestamp");
        if (!DateTimeOffset.TryParse(
                timestampText,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var timestamp))
        {
            throw SchemaInvalid("The response timestamp was invalid.");
        }

        var vulnerabilities = RequireArray(root, "vulnerabilities");
        if (vulnerabilities.GetArrayLength() != resultsPerPage ||
            startIndex + resultsPerPage > totalResults)
        {
            throw SchemaInvalid("The response pagination counts were inconsistent.");
        }

        var advisories = new List<ParsedAdvisory>(resultsPerPage);
        foreach (var wrapperElement in vulnerabilities.EnumerateArray())
        {
            var wrapper = RequireObject(wrapperElement, "vulnerability");
            if (!wrapper.TryGetProperty("cve", out var cveElement))
            {
                throw SchemaInvalid("A vulnerability record did not contain a cve object.");
            }

            advisories.Add(ParseAdvisory(
                RequireObject(cveElement, "cve"),
                queriedCpe23Uri));
        }

        return new(startIndex, resultsPerPage, totalResults, timestamp, advisories);
    }

    private ParsedAdvisory ParseAdvisory(
        JsonElement cve,
        string queriedCpe23Uri)
    {
        var id = RequireString(cve, "id").ToUpperInvariant();
        if (!CveIdRegex().IsMatch(id))
        {
            throw SchemaInvalid("A vulnerability record contained an invalid CVE identifier.");
        }

        _ = RequireString(cve, "sourceIdentifier");
        _ = RequireDate(cve, "published");
        var lastModified = RequireDate(cve, "lastModified");
        var status = NormalizeNvdStatus(RequireString(cve, "vulnStatus"));

        var descriptions = RequireArray(cve, "descriptions");
        if (descriptions.GetArrayLength() == 0)
        {
            throw SchemaInvalid("A vulnerability record had no descriptions.");
        }

        var englishDescriptions = new List<string>();
        foreach (var descriptionElement in descriptions.EnumerateArray())
        {
            var description = RequireObject(descriptionElement, "description");
            var language = RequireString(description, "lang");
            var value = RequireString(description, "value");
            if (value.Length > 8192)
            {
                throw SchemaInvalid("A vulnerability description exceeded the safety cap.");
            }

            if (string.Equals(language, "en", StringComparison.OrdinalIgnoreCase))
            {
                englishDescriptions.Add(value);
            }
        }

        var referencesElement = RequireArray(cve, "references");
        var allReferences = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var referenceElement in referencesElement.EnumerateArray())
        {
            var reference = RequireObject(referenceElement, "reference");
            var value = RequireString(reference, "url");
            if (value.Length > 4096 ||
                !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            {
                throw SchemaInvalid("A vulnerability reference URL was invalid.");
            }

            allReferences.Add(uri.AbsoluteUri);
        }

        var severity = ParseSeverity(cve);
        var references = allReferences.Take(_options.MaxReferencesPerAdvisory).ToArray();
        var emitMatch = status is "Analyzed" or "Modified";
        var applicability = emitMatch
            ? ParseApplicability(cve, queriedCpe23Uri)
            : new RemoteAdvisoryApplicability(
                RemoteAdvisoryApplicabilityDisposition.Inconclusive,
                false,
                false,
                [],
                ["NVD enrichment is incomplete, so no applicability claim was emitted."]);
        return new(
            id,
            status,
            lastModified,
            emitMatch,
            applicability,
            severity.Severity,
            severity.Source,
            englishDescriptions.Order(StringComparer.Ordinal).FirstOrDefault(),
            references,
            allReferences.Count > references.Length);
    }

    private static string NormalizeNvdStatus(string value) => value switch
    {
        "Analyzed" => "Analyzed",
        "Modified" => "Modified",
        "Received" => "Received",
        "Awaiting Analysis" or "AwaitingAnalysis" => "Awaiting Analysis",
        "Undergoing Analysis" or "UndergoingAnalysis" => "Undergoing Analysis",
        "Deferred" => "Deferred",
        "Rejected" => throw SchemaInvalid(
            "A rejected CVE was returned despite the noRejected filter."),
        _ => throw SchemaInvalid("A vulnerability record contained an unknown NVD status."),
    };

    private static RemoteAdvisoryApplicability ParseApplicability(
        JsonElement cve,
        string queriedCpe23Uri)
    {
        var configurationsElement = RequireArray(cve, "configurations");
        if (configurationsElement.GetArrayLength() == 0)
        {
            throw SchemaInvalid("An enriched vulnerability had no applicability configurations.");
        }

        var configurations = new List<RemoteAdvisoryConfiguration>();
        var directBranchFound = false;
        var conditionalBranchFound = false;
        var negatedBranchFound = false;
        var inconclusiveBranchFound = false;
        var inconclusiveConstraintFound = false;
        var queriedLeafFound = false;

        foreach (var configurationElement in configurationsElement.EnumerateArray())
        {
            var configuration = RequireObject(configurationElement, "configuration");
            var configurationOperator = OptionalOperator(configuration, "operator");
            var configurationNegate = OptionalBoolean(configuration, "negate");
            var nodesElement = RequireArray(configuration, "nodes");
            if (nodesElement.GetArrayLength() == 0)
            {
                throw SchemaInvalid("An applicability configuration had no nodes.");
            }

            var nodes = new List<RemoteAdvisoryApplicabilityNode>();
            foreach (var nodeElement in nodesElement.EnumerateArray())
            {
                var node = RequireObject(nodeElement, "applicability node");
                var nodeOperator = RequireOperator(node, "operator");
                var nodeNegate = OptionalBoolean(node, "negate");
                var cpeMatchesElement = RequireArray(node, "cpeMatch");
                if (cpeMatchesElement.GetArrayLength() == 0)
                {
                    throw SchemaInvalid("An applicability node had no CPE match criteria.");
                }

                var cpeMatches = new List<RemoteAdvisoryCpeMatch>();
                foreach (var cpeMatchElement in cpeMatchesElement.EnumerateArray())
                {
                    var cpeMatch = RequireObject(cpeMatchElement, "CPE match criterion");
                    var vulnerable = RequireBoolean(cpeMatch, "vulnerable");
                    var criteria = RequireString(cpeMatch, "criteria");
                    if (!TryValidateMatchCriteria(criteria))
                    {
                        throw SchemaInvalid("An applicability criterion was not a valid CPE 2.3 match string.");
                    }

                    var matchCriteriaId = RequireString(cpeMatch, "matchCriteriaId");
                    if (!Guid.TryParse(matchCriteriaId, out _))
                    {
                        throw SchemaInvalid("An applicability criterion identifier was not a UUID.");
                    }

                    var versionStartExcluding = OptionalBound(cpeMatch, "versionStartExcluding");
                    var versionStartIncluding = OptionalBound(cpeMatch, "versionStartIncluding");
                    var versionEndExcluding = OptionalBound(cpeMatch, "versionEndExcluding");
                    var versionEndIncluding = OptionalBound(cpeMatch, "versionEndIncluding");
                    var alignment = AlignQueriedIdentity(
                        criteria,
                        queriedCpe23Uri,
                        versionStartExcluding,
                        versionStartIncluding,
                        versionEndExcluding,
                        versionEndIncluding);
                    var identityAlignment = vulnerable
                        ? alignment
                        : RemoteAdvisoryCpeAlignment.NoMatch;
                    var matchesIdentity =
                        identityAlignment == RemoteAdvisoryCpeAlignment.Proven;
                    inconclusiveConstraintFound |= identityAlignment ==
                        RemoteAdvisoryCpeAlignment.InconclusiveConstraint;
                    queriedLeafFound |= matchesIdentity;
                    cpeMatches.Add(new(
                        vulnerable,
                        criteria,
                        matchCriteriaId,
                        versionStartExcluding,
                        versionStartIncluding,
                        versionEndExcluding,
                        versionEndIncluding,
                        identityAlignment,
                        matchesIdentity,
                        identityAlignment ==
                            RemoteAdvisoryCpeAlignment.ConditionalOnUnobservedQualifier));
                }

                ValidateRangePairs(cpeMatches);
                var parsedNode = new RemoteAdvisoryApplicabilityNode(
                    nodeOperator,
                    nodeNegate,
                    cpeMatches);
                nodes.Add(parsedNode);
            }

            var parsedConfiguration = new RemoteAdvisoryConfiguration(
                configurationOperator,
                configurationNegate,
                nodes);
            configurations.Add(parsedConfiguration);

            var nodeDispositions = nodes
                .Select(EvaluateNode)
                .ToArray();
            if (!nodeDispositions.Any(static disposition =>
                    disposition != ApplicabilityBranchDisposition.NoMatch))
            {
                continue;
            }

            if (configurationNegate)
            {
                negatedBranchFound = true;
                continue;
            }

            var configurationDisposition = EvaluateConfiguration(
                configurationOperator,
                nodes,
                nodeDispositions);
            if (configurationDisposition == ApplicabilityBranchDisposition.Direct)
            {
                directBranchFound = true;
            }
            else if (configurationDisposition == ApplicabilityBranchDisposition.Conditional)
            {
                conditionalBranchFound = true;
            }
            else
            {
                inconclusiveBranchFound = true;
                negatedBranchFound |=
                    (string.Equals(configurationOperator, "AND", StringComparison.Ordinal) &&
                     nodes.Any(static node => node.Negate)) ||
                    nodes.Any(static node =>
                        node.Negate && node.CpeMatches.Any(static match =>
                            match.IdentityAlignment != RemoteAdvisoryCpeAlignment.NoMatch));
            }
        }

        RemoteAdvisoryApplicabilityDisposition disposition;
        IReadOnlyList<string> limitations;
        if (directBranchFound)
        {
            disposition = RemoteAdvisoryApplicabilityDisposition.DirectCandidate;
            limitations =
            [
                "The NVD CPE association is a candidate match; affected code and exploitability were not assessed.",
            ];
        }
        else if (conditionalBranchFound)
        {
            disposition = RemoteAdvisoryApplicabilityDisposition.ConditionalCandidate;
            limitations =
            [
                "The matching NVD applicability branch contains required cofactors that were not observed remotely.",
                "Affected code and exploitability were not assessed.",
            ];
        }
        else
        {
            disposition = RemoteAdvisoryApplicabilityDisposition.Inconclusive;
            limitations = negatedBranchFound
                ?
                [
                    "The matching NVD applicability branch uses negation and cannot be safely reduced to a target claim.",
                    "Affected code and exploitability were not assessed.",
                ]
                : inconclusiveConstraintFound && inconclusiveBranchFound
                    ?
                    [
                        "The matching product branch uses an NVD range or pattern that cannot be attributed to one leaf from the CVE response alone.",
                        "Affected code and exploitability were not assessed.",
                    ]
                :
                [
                    "The API returned the CVE, but no vulnerable criterion could be conservatively aligned to the queried identity.",
                    "Affected code and exploitability were not assessed.",
                ];
        }

        return new(
            disposition,
            queriedLeafFound,
            disposition == RemoteAdvisoryApplicabilityDisposition.ConditionalCandidate,
            configurations,
            limitations);
    }

    private static ApplicabilityBranchDisposition EvaluateNode(
        RemoteAdvisoryApplicabilityNode node)
    {
        var matchingLeaves = node.CpeMatches
            .Where(static match =>
                match.IdentityAlignment != RemoteAdvisoryCpeAlignment.NoMatch)
            .ToArray();
        if (matchingLeaves.Length == 0)
        {
            return ApplicabilityBranchDisposition.NoMatch;
        }

        if (node.Negate)
        {
            return ApplicabilityBranchDisposition.Inconclusive;
        }

        if (string.Equals(node.Operator, "OR", StringComparison.Ordinal))
        {
            if (matchingLeaves.Any(static match =>
                    match.IdentityAlignment == RemoteAdvisoryCpeAlignment.Proven))
            {
                return ApplicabilityBranchDisposition.Direct;
            }

            return matchingLeaves.Any(static match =>
                    match.IdentityAlignment ==
                        RemoteAdvisoryCpeAlignment.ConditionalOnUnobservedQualifier)
                ? ApplicabilityBranchDisposition.Conditional
                : ApplicabilityBranchDisposition.Inconclusive;
        }

        if (matchingLeaves.Any(static match =>
                match.IdentityAlignment ==
                    RemoteAdvisoryCpeAlignment.InconclusiveConstraint))
        {
            return ApplicabilityBranchDisposition.Inconclusive;
        }

        return node.CpeMatches.All(static match =>
                match.Vulnerable &&
                match.MatchesQueriedIdentity &&
                !match.HasUnobservedQualifiers)
            ? ApplicabilityBranchDisposition.Direct
            : ApplicabilityBranchDisposition.Conditional;
    }

    private static ApplicabilityBranchDisposition EvaluateConfiguration(
        string? configurationOperator,
        IReadOnlyList<RemoteAdvisoryApplicabilityNode> nodes,
        IReadOnlyList<ApplicabilityBranchDisposition> nodeDispositions)
    {
        if (string.Equals(configurationOperator, "OR", StringComparison.Ordinal))
        {
            if (nodeDispositions.Contains(ApplicabilityBranchDisposition.Direct))
            {
                return ApplicabilityBranchDisposition.Direct;
            }

            if (nodeDispositions.Contains(ApplicabilityBranchDisposition.Conditional))
            {
                return ApplicabilityBranchDisposition.Conditional;
            }

            return ApplicabilityBranchDisposition.Inconclusive;
        }

        if (string.Equals(configurationOperator, "AND", StringComparison.Ordinal))
        {
            if (nodes.Any(static node => node.Negate) ||
                nodeDispositions.Contains(ApplicabilityBranchDisposition.Inconclusive))
            {
                return ApplicabilityBranchDisposition.Inconclusive;
            }

            return nodeDispositions.All(static disposition =>
                    disposition == ApplicabilityBranchDisposition.Direct)
                ? ApplicabilityBranchDisposition.Direct
                : ApplicabilityBranchDisposition.Conditional;
        }

        if (nodes.Count == 1)
        {
            return nodeDispositions[0];
        }

        return nodes.Any(static node => node.Negate) ||
            nodeDispositions.Contains(ApplicabilityBranchDisposition.Inconclusive)
            ? ApplicabilityBranchDisposition.Inconclusive
            : ApplicabilityBranchDisposition.Conditional;
    }

    private static string RequireOperator(JsonElement parent, string propertyName) =>
        OptionalOperator(parent, propertyName) ??
        throw SchemaInvalid($"The required {propertyName} operator was missing.");

    private static string? OptionalOperator(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value))
        {
            return null;
        }

        var result = RequireStringValue(value, propertyName);
        return result is "AND" or "OR"
            ? result
            : throw SchemaInvalid($"The {propertyName} operator was invalid.");
    }

    private static bool OptionalBoolean(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value))
        {
            return false;
        }

        return RequireBooleanValue(value, propertyName);
    }

    private static bool RequireBoolean(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value))
        {
            throw SchemaInvalid($"The required {propertyName} boolean was missing.");
        }

        return RequireBooleanValue(value, propertyName);
    }

    private static bool RequireBooleanValue(JsonElement value, string propertyName)
    {
        if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw SchemaInvalid($"The {propertyName} boolean was invalid.");
        }

        return value.GetBoolean();
    }

    private static string? OptionalBound(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value))
        {
            return null;
        }

        var result = RequireStringValue(value, propertyName);
        if (result.Length > 128)
        {
            throw SchemaInvalid($"The {propertyName} value exceeded the safety cap.");
        }

        return result;
    }

    private static void ValidateRangePairs(IEnumerable<RemoteAdvisoryCpeMatch> matches)
    {
        foreach (var match in matches)
        {
            if (match.VersionStartExcluding is not null && match.VersionStartIncluding is not null ||
                match.VersionEndExcluding is not null && match.VersionEndIncluding is not null)
            {
                throw SchemaInvalid("An applicability criterion contained conflicting version bounds.");
            }
        }
    }

    private static bool TryValidateMatchCriteria(string criteria)
    {
        if (criteria.Length > 512 || criteria.Any(static character =>
                char.IsControl(character) || char.IsWhiteSpace(character)))
        {
            return false;
        }

        var components = SplitCpeComponents(criteria);
        return components is { Count: 13 } &&
            string.Equals(components[0], "cpe", StringComparison.Ordinal) &&
            string.Equals(components[1], "2.3", StringComparison.Ordinal) &&
            components.Skip(2).All(static component => component.Length > 0);
    }

    private static RemoteAdvisoryCpeAlignment AlignQueriedIdentity(
        string criteria,
        string queriedCpe23Uri,
        string? versionStartExcluding,
        string? versionStartIncluding,
        string? versionEndExcluding,
        string? versionEndIncluding)
    {
        var criterionComponents = SplitCpeComponents(criteria);
        var queryComponents = SplitCpeComponents(queriedCpe23Uri);
        if (criterionComponents is not { Count: 13 } || queryComponents is not { Count: 13 })
        {
            return RemoteAdvisoryCpeAlignment.NoMatch;
        }

        if (!Enumerable.Range(2, 3).All(index =>
                !string.Equals(criterionComponents[index], "*", StringComparison.Ordinal) &&
                string.Equals(
                    criterionComponents[index],
                    queryComponents[index],
                    StringComparison.OrdinalIgnoreCase)))
        {
            return RemoteAdvisoryCpeAlignment.NoMatch;
        }

        var queryVersion = queryComponents[5];
        var criterionVersion = criterionComponents[5];
        if (queryVersion is "*" or "-" || criterionVersion == "-")
        {
            return RemoteAdvisoryCpeAlignment.NoMatch;
        }

        var unsupportedConstraint = false;
        if (criterionVersion != "*")
        {
            if (criterionVersion.Contains('*') || criterionVersion.Contains('?'))
            {
                unsupportedConstraint = true;
            }
            else if (!string.Equals(
                         criterionVersion,
                         queryVersion,
                         StringComparison.OrdinalIgnoreCase))
            {
                return RemoteAdvisoryCpeAlignment.NoMatch;
            }
        }

        var hasUnobservedQualifiers = false;
        for (var index = 6; index < criterionComponents.Count; index++)
        {
            var criterion = criterionComponents[index];
            var query = queryComponents[index];
            if (criterion == "*")
            {
                continue;
            }

            if (criterion.Contains('*') || criterion.Contains('?'))
            {
                unsupportedConstraint = true;
                continue;
            }

            if (string.Equals(criterion, query, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (query == "*")
            {
                hasUnobservedQualifiers = true;
                continue;
            }

            return RemoteAdvisoryCpeAlignment.NoMatch;
        }

        if (unsupportedConstraint ||
            versionStartExcluding is not null ||
            versionStartIncluding is not null ||
            versionEndExcluding is not null ||
            versionEndIncluding is not null)
        {
            // The CVE endpoint tells us that some match criterion admitted the
            // requested CPE, but it does not identify which leaf or expand the
            // Match Criteria dictionary set. Never attribute a range or pattern
            // to this leaf without a second data source.
            return RemoteAdvisoryCpeAlignment.InconclusiveConstraint;
        }

        return hasUnobservedQualifiers
            ? RemoteAdvisoryCpeAlignment.ConditionalOnUnobservedQualifier
            : RemoteAdvisoryCpeAlignment.Proven;
    }

    private static ParsedSeverity ParseSeverity(JsonElement cve)
    {
        if (!cve.TryGetProperty("metrics", out var metricsElement))
        {
            return new(RemoteAdvisorySeverity.Unknown, null, 0, false);
        }

        var metrics = RequireObject(metricsElement, "metrics");
        var candidates = new List<ParsedSeverity>();
        ParseMetricArray(metrics, "cvssMetricV40", "4.0", 4, candidates);
        ParseMetricArray(metrics, "cvssMetricV31", "3.1", 3, candidates);
        ParseMetricArray(metrics, "cvssMetricV30", "3.0", 2, candidates);
        ParseMetricArray(metrics, "cvssMetricV2", "2.0", 1, candidates);

        return candidates
            .OrderByDescending(static candidate => candidate.VersionPriority)
            .ThenByDescending(static candidate => candidate.IsPrimary)
            .ThenBy(static candidate => candidate.Source, StringComparer.Ordinal)
            .ThenByDescending(static candidate => candidate.Severity)
            .FirstOrDefault() ?? new(RemoteAdvisorySeverity.Unknown, null, 0, false);
    }

    private static void ParseMetricArray(
        JsonElement metrics,
        string propertyName,
        string expectedVersion,
        int versionPriority,
        ICollection<ParsedSeverity> output)
    {
        if (!metrics.TryGetProperty(propertyName, out var arrayElement))
        {
            return;
        }

        if (arrayElement.ValueKind != JsonValueKind.Array || arrayElement.GetArrayLength() == 0)
        {
            throw SchemaInvalid($"The {propertyName} metric collection was invalid.");
        }

        foreach (var metricElement in arrayElement.EnumerateArray())
        {
            var metric = RequireObject(metricElement, propertyName);
            var source = RequireString(metric, "source");
            var type = RequireString(metric, "type");
            if (!metric.TryGetProperty("cvssData", out var cvssDataElement))
            {
                throw SchemaInvalid($"A {propertyName} metric did not contain cvssData.");
            }

            var cvssData = RequireObject(cvssDataElement, "cvssData");
            var version = RequireString(cvssData, "version");
            _ = RequireString(cvssData, "vectorString");
            var baseScore = RequireNumber(cvssData, "baseScore");
            if (!string.Equals(version, expectedVersion, StringComparison.Ordinal) ||
                baseScore is < 0 or > 10)
            {
                throw SchemaInvalid($"A {propertyName} metric contained invalid CVSS data.");
            }

            string severityText;
            if (cvssData.TryGetProperty("baseSeverity", out var severityElement))
            {
                severityText = RequireStringValue(severityElement, "baseSeverity");
            }
            else
            {
                severityText = RequireString(metric, "baseSeverity");
            }

            var severity = severityText.ToUpperInvariant() switch
            {
                "LOW" => RemoteAdvisorySeverity.Low,
                "MEDIUM" => RemoteAdvisorySeverity.Medium,
                "HIGH" => RemoteAdvisorySeverity.High,
                "CRITICAL" => RemoteAdvisorySeverity.Critical,
                "NONE" => RemoteAdvisorySeverity.Unknown,
                _ => throw SchemaInvalid($"A {propertyName} metric contained an unknown severity."),
            };
            output.Add(new(
                severity,
                $"{source}/CVSS:{version}",
                versionPriority,
                string.Equals(type, "Primary", StringComparison.OrdinalIgnoreCase)));
        }
    }

    private IReadOnlyList<RemoteAdvisoryMatch> CreateMatches(
        IReadOnlyList<ParsedAdvisory> advisories,
        RemoteAdvisoryIdentity identity,
        string cpe23Uri) =>
        advisories
            .OrderBy(static advisory => advisory.AdvisoryId, StringComparer.Ordinal)
            .Select(advisory => CreateMatch(advisory, identity, cpe23Uri))
            .ToArray();

    private static RemoteAdvisoryMatch CreateMatch(
        ParsedAdvisory advisory,
        RemoteAdvisoryIdentity identity,
        string cpe23Uri)
        => new(
            advisory.AdvisoryId,
            advisory.Applicability.Disposition switch
            {
                RemoteAdvisoryApplicabilityDisposition.DirectCandidate => "candidate",
                RemoteAdvisoryApplicabilityDisposition.ConditionalCandidate => "conditional_candidate",
                _ => "inconclusive",
            },
            "remote_banner_match",
            identity.Product,
            identity.Version,
            cpe23Uri,
            identity.Evidence,
            identity.Confidence,
            advisory.NvdStatus,
            advisory.NvdLastModified,
            advisory.Applicability,
            advisory.Severity,
            advisory.SeveritySource,
            advisory.Description,
            advisory.References,
            advisory.ReferencesTruncated,
            "not_assessed");

    private static RequestValidationFailure? ValidateRequest(RemoteAdvisoryRequest request)
    {
        if (request.Identity is null)
        {
            return new(RemoteAdvisoryStatus.Unresolved, "identity_missing", "A remote product identity is required.");
        }

        var identity = request.Identity;
        if (identity.CpeResolution is null)
        {
            return new(
                RemoteAdvisoryStatus.Unresolved,
                "cpe_unresolved",
                "A verified banner-catalog CPE resolution is required; no network request was made.");
        }

        if (!identity.CpeResolution.IsResolved)
        {
            return new(
                RemoteAdvisoryStatus.Unresolved,
                identity.CpeResolution.Diagnostic?.Code ?? "cpe_unresolved",
                identity.CpeResolution.Diagnostic?.Message ??
                    "The banner identity did not resolve to a verified CPE.");
        }

        if (identity.Confidence is not (RemoteAdvisoryConfidence.Exact or RemoteAdvisoryConfidence.Strong))
        {
            return new(
                RemoteAdvisoryStatus.Unresolved,
                "identity_confidence_insufficient",
                "Heuristic or unresolved identities are not sent to the NVD API.");
        }

        if (string.IsNullOrWhiteSpace(identity.Product) || identity.Product.Length > 128 ||
            string.IsNullOrWhiteSpace(identity.Version) || identity.Version.Length > 64 ||
            string.IsNullOrWhiteSpace(identity.Evidence) || identity.Evidence.Length > 1024)
        {
            return new(
                RemoteAdvisoryStatus.Unresolved,
                "identity_invalid",
                "Product, version, or evidence was missing or exceeded its safety cap.");
        }

        if (!string.Equals(
                identity.CpeResolution.Provenance,
                RemoteBannerCpeCatalog.Resolution.VerifiedCatalogProvenance,
                StringComparison.Ordinal) ||
            !identity.CpeResolution.MatchesIdentity(identity))
        {
            return new(
                RemoteAdvisoryStatus.Unresolved,
                "cpe_identity_binding_mismatch",
                "The catalog CPE resolution was not bound to the supplied banner identity.");
        }

        if (string.IsNullOrWhiteSpace(identity.CpeResolution.Cpe23Uri) ||
            !TryValidateExactCpe(identity.CpeResolution.Cpe23Uri))
        {
            return new(
                RemoteAdvisoryStatus.Unresolved,
                "cpe_invalid",
                "The supplied CPE was not an exact CPE 2.3 URI.");
        }

        if (request.NvdApiKey is not null &&
            (request.NvdApiKey.Length is < 1 or > 256 ||
             request.NvdApiKey.Any(char.IsControl) ||
             request.NvdApiKey.Any(char.IsWhiteSpace)))
        {
            return new(
                RemoteAdvisoryStatus.Failed,
                "nvd_api_key_invalid",
                "The caller-supplied NVD API key was not a valid header value.");
        }

        return null;
    }

    private static bool TryValidateExactCpe(string cpe23Uri)
    {
        if (cpe23Uri.Length > 512 || cpe23Uri.Any(static character =>
                char.IsControl(character) || char.IsWhiteSpace(character)))
        {
            return false;
        }

        var components = SplitCpeComponents(cpe23Uri);
        if (components is null || components.Count != 13 ||
            !string.Equals(components[0], "cpe", StringComparison.Ordinal) ||
            !string.Equals(components[1], "2.3", StringComparison.Ordinal) ||
            components[2] is not ("a" or "o" or "h") ||
            components.Skip(2).Any(string.IsNullOrEmpty) ||
            components[3] is "*" or "-" ||
            components[4] is "*" or "-" ||
            components[5] is "*" or "-")
        {
            return false;
        }

        return true;
    }

    private static IReadOnlyList<string>? SplitCpeComponents(string value)
    {
        var components = new List<string>();
        var start = 0;
        var escaped = false;
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (escaped)
            {
                escaped = false;
                continue;
            }

            if (character == '\\')
            {
                escaped = true;
                continue;
            }

            if (character == ':')
            {
                components.Add(value[start..index]);
                start = index + 1;
            }
        }

        if (escaped)
        {
            return null;
        }

        components.Add(value[start..]);
        return components;
    }

    private static JsonElement RequireObject(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw SchemaInvalid($"The {name} value was not an object.");
        }

        return element;
    }

    private static JsonElement RequireArray(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.Array)
        {
            throw SchemaInvalid($"The required {propertyName} array was missing or invalid.");
        }

        return value;
    }

    private static string RequireString(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value))
        {
            throw SchemaInvalid($"The required {propertyName} value was missing.");
        }

        return RequireStringValue(value, propertyName);
    }

    private static string RequireStringValue(JsonElement value, string propertyName)
    {
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw SchemaInvalid($"The required {propertyName} string was invalid.");
        }

        return value.GetString()!;
    }

    private static int RequireNonNegativeInt(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt32(out var result) ||
            result < 0)
        {
            throw SchemaInvalid($"The required {propertyName} integer was invalid.");
        }

        return result;
    }

    private static double RequireNumber(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetDouble(out var result) ||
            !double.IsFinite(result))
        {
            throw SchemaInvalid($"The required {propertyName} number was invalid.");
        }

        return result;
    }

    private static DateTimeOffset RequireDate(JsonElement parent, string propertyName)
    {
        var text = RequireString(parent, propertyName);
        if (!DateTimeOffset.TryParse(
                text,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var result))
        {
            throw SchemaInvalid($"The required {propertyName} timestamp was invalid.");
        }

        return result;
    }

    private static NvdResponseException SchemaInvalid(string message) =>
        new(RemoteAdvisoryStatus.Failed, "nvd_schema_invalid", message);

    private static RemoteAdvisoryResult Result(
        RemoteAdvisoryStatus status,
        string networkMode,
        string code,
        string message) =>
        new(
            status,
            RemoteAdvisoryResult.ProviderName,
            networkMode,
            null,
            [],
            [new(code, message)]);

    [GeneratedRegex("^CVE-[0-9]{4}-[0-9]{4,}$", RegexOptions.CultureInvariant)]
    private static partial Regex CveIdRegex();

    private enum ApplicabilityBranchDisposition
    {
        NoMatch,
        Direct,
        Conditional,
        Inconclusive,
    }

    private sealed record RequestValidationFailure(
        RemoteAdvisoryStatus Status,
        string Code,
        string Message);

    private sealed record ParsedPage(
        int StartIndex,
        int ResultCount,
        int TotalResults,
        DateTimeOffset Timestamp,
        IReadOnlyList<ParsedAdvisory> Advisories);

    private sealed record ParsedAdvisory(
        string AdvisoryId,
        string NvdStatus,
        DateTimeOffset NvdLastModified,
        bool EmitMatch,
        RemoteAdvisoryApplicability Applicability,
        RemoteAdvisorySeverity Severity,
        string? SeveritySource,
        string? Description,
        IReadOnlyList<string> References,
        bool ReferencesTruncated);

    private sealed record ParsedSeverity(
        RemoteAdvisorySeverity Severity,
        string? Source,
        int VersionPriority,
        bool IsPrimary);

    private sealed class NvdResponseException(
        RemoteAdvisoryStatus status,
        string code,
        string message) : Exception(message)
    {
        internal RemoteAdvisoryStatus Status { get; } = status;
        internal string Code { get; } = code;
    }
}

internal sealed record NvdAdvisoryClientOptions(
    int ResultsPerPage,
    int MaxRequests,
    int MaxCandidates,
    int MaxResponseBytes,
    int MaxReferencesPerAdvisory,
    TimeSpan RequestTimeout)
{
    internal static NvdAdvisoryClientOptions Default { get; } = new(
        ResultsPerPage: 100,
        MaxRequests: 3,
        MaxCandidates: 250,
        MaxResponseBytes: 4 * 1024 * 1024,
        MaxReferencesPerAdvisory: 20,
        RequestTimeout: TimeSpan.FromSeconds(30));

    internal void Validate()
    {
        if (ResultsPerPage is < 1 or > 2000 ||
            MaxRequests is < 1 or > 10 ||
            MaxCandidates < ResultsPerPage ||
            MaxCandidates > ResultsPerPage * MaxRequests ||
            MaxResponseBytes is < 1024 or > 16 * 1024 * 1024 ||
            MaxReferencesPerAdvisory is < 1 or > 100 ||
            RequestTimeout <= TimeSpan.Zero || RequestTimeout > TimeSpan.FromMinutes(2))
        {
            throw new ArgumentOutOfRangeException(
                nameof(NvdAdvisoryClientOptions),
                "NVD client limits were outside the supported safety bounds.");
        }
    }
}
