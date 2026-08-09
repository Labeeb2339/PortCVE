using PortCVE.Cli;

using var cancellationSource = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellationSource.Cancel();
};

try
{
    var options = CliParser.Parse(args);
    return await new CliApplication().RunAsync(
        options,
        Console.Out,
        Console.Error,
        cancellationSource.Token);
}
catch (CliUsageException exception)
{
    Console.Error.WriteLine($"error: {exception.Message}");
    Console.Error.WriteLine("Run 'portcve help' for usage.");
    return ExitCodes.UsageOrSchema;
}
catch (OperationCanceledException)
{
    return ExitCodes.Interrupted;
}
catch (Exception exception)
{
    Console.Error.WriteLine($"error: {exception.Message}");
    return ExitCodes.RuntimeFailure;
}
