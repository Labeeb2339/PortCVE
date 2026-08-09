using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using PortCVE.Domain;

namespace PortCVE.Collection;

public sealed class WindowsDockerEngineCollector
{
    private const string CollectorName = "docker";
    private const string PipeName = "docker_engine";
    private const string PipePath = @"\\.\pipe\docker_engine";
    private const uint PipeProbeTimeoutMilliseconds = 25;
    private const int PipeConnectTimeoutMilliseconds = 500;
    private const long MaxVersionResponseBytes = 64 * 1024;
    private const long MaxContainersResponseBytes = 8 * 1024 * 1024;
    private static readonly TimeSpan OverallTimeout = TimeSpan.FromSeconds(3);

    public async Task<CollectionResult<IReadOnlyList<DockerPublishedPort>>> CollectAsync(
        CancellationToken cancellationToken)
    {
        var observedAt = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();

        if (!OperatingSystem.IsWindows())
        {
            return Unavailable(
                observedAt,
                stopwatch,
                "platform_unsupported",
                "Docker Engine named-pipe collection is available only on Windows.");
        }

        if (!NativeMethods.WaitNamedPipe(PipePath, PipeProbeTimeoutMilliseconds))
        {
            return Unavailable(
                observedAt,
                stopwatch,
                Marshal.GetLastWin32Error() == NativeMethods.ErrorAccessDenied
                    ? "docker_access_denied"
                    : "docker_unavailable",
                "Docker Engine named pipe is not currently available.");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(OverallTimeout);

        try
        {
            using var handler = CreateHandler();
            using var client = new HttpClient(handler)
            {
                BaseAddress = new("http://docker-engine/", UriKind.Absolute),
                Timeout = System.Threading.Timeout.InfiniteTimeSpan,
                DefaultRequestVersion = HttpVersion.Version11,
                DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
            };
            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("portcve", "0.1"));

            using var versionResponse = await client.GetAsync(
                "/version",
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token);
            var versionJson = await ReadResponseAsync(
                versionResponse,
                MaxVersionResponseBytes,
                timeout.Token);
            var apiVersion = DockerPublishedPortParser.ParseApiVersion(versionJson);

            using var containersResponse = await client.GetAsync(
                $"/v{apiVersion}/containers/json",
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token);
            var containersJson = await ReadResponseAsync(
                containersResponse,
                MaxContainersResponseBytes,
                timeout.Token);
            var ports = DockerPublishedPortParser.ParseContainers(containersJson);

            stopwatch.Stop();
            return CollectionResult<IReadOnlyList<DockerPublishedPort>>.Complete(
                CollectorName,
                observedAt,
                stopwatch.ElapsedMilliseconds,
                ports);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Unavailable(
                observedAt,
                stopwatch,
                "docker_timeout",
                $"Docker Engine did not respond within {OverallTimeout.TotalSeconds:0.#} seconds.");
        }
        catch (JsonException exception)
        {
            stopwatch.Stop();
            var diagnostic = new CollectorDiagnostic(
                CollectorName,
                CollectorStatus.Failed,
                "docker_json_invalid",
                exception.Message);
            return new(
                [],
                new(CollectorName, CollectorStatus.Failed, observedAt, stopwatch.ElapsedMilliseconds, [diagnostic]));
        }
        catch (HttpRequestException exception) when (exception.StatusCode is not null)
        {
            stopwatch.Stop();
            var diagnostic = new CollectorDiagnostic(
                CollectorName,
                CollectorStatus.Failed,
                "docker_api_error",
                $"Docker Engine API returned HTTP {(int)exception.StatusCode.Value}.");
            return new(
                [],
                new(CollectorName, CollectorStatus.Failed, observedAt, stopwatch.ElapsedMilliseconds, [diagnostic]));
        }
        catch (UnauthorizedAccessException)
        {
            return Unavailable(
                observedAt,
                stopwatch,
                "docker_access_denied",
                "Access to the Docker Engine named pipe was denied.");
        }
        catch (HttpRequestException exception) when (ContainsException<UnauthorizedAccessException>(exception))
        {
            return Unavailable(
                observedAt,
                stopwatch,
                "docker_access_denied",
                "Access to the Docker Engine named pipe was denied.");
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or TimeoutException)
        {
            return Unavailable(
                observedAt,
                stopwatch,
                "docker_unavailable",
                $@"Docker Engine is unavailable through \\.\pipe\docker_engine: {exception.Message}");
        }
    }

    private static SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        ConnectCallback = ConnectToNamedPipeAsync,
    };

    private static async ValueTask<Stream> ConnectToNamedPipeAsync(
        SocketsHttpConnectionContext _,
        CancellationToken cancellationToken)
    {
        var pipe = new NamedPipeClientStream(
            ".",
            PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(PipeConnectTimeoutMilliseconds, cancellationToken);
            return pipe;
        }
        catch
        {
            pipe.Dispose();
            throw;
        }
    }

    private static async Task<string> ReadResponseAsync(
        HttpResponseMessage response,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        response.EnsureSuccessStatusCode();
        await response.Content.LoadIntoBufferAsync(maximumBytes, cancellationToken);
        return await response.Content.ReadAsStringAsync(cancellationToken);
    }

    private static CollectionResult<IReadOnlyList<DockerPublishedPort>> Unavailable(
        DateTimeOffset observedAt,
        Stopwatch stopwatch,
        string code,
        string message)
    {
        stopwatch.Stop();
        var diagnostic = new CollectorDiagnostic(
            CollectorName,
            CollectorStatus.Unavailable,
            code,
            message);
        return new(
            [],
            new(CollectorName, CollectorStatus.Unavailable, observedAt, stopwatch.ElapsedMilliseconds, [diagnostic]));
    }

    private static bool ContainsException<TException>(Exception exception)
        where TException : Exception
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is TException)
            {
                return true;
            }
        }

        return false;
    }

    private static class NativeMethods
    {
        public const int ErrorAccessDenied = 5;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WaitNamedPipe(string name, uint timeout);
    }
}
