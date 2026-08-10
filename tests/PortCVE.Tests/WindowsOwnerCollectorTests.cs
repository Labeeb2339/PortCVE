using System.Security.Cryptography;
using PortCVE.Collection;

namespace PortCVE.Tests;

public sealed class WindowsOwnerCollectorTests
{
    [Fact]
    public void TryHashBinary_RejectsUncPathBeforeOpeningIt()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var limitations = new List<string>();

        var digest = WindowsOwnerCollector.TryHashBinary(
            @"\\127.0.0.1\portcve-never-connect\app.exe",
            limitations);

        Assert.Null(digest);
        Assert.Contains(limitations, static limitation =>
            limitation.Contains("validated local", StringComparison.Ordinal));
    }

    [Fact]
    public void TryHashBinary_HashesValidatedLocalFile()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var path = Path.Combine(Path.GetTempPath(), $"portcve-owner-{Guid.NewGuid():N}.exe");
        var content = new byte[] { 1, 3, 3, 7 };
        File.WriteAllBytes(path, content);
        try
        {
            var limitations = new List<string>();

            var digest = WindowsOwnerCollector.TryHashBinary(path, limitations);

            Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(content)), digest);
            Assert.Empty(limitations);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
