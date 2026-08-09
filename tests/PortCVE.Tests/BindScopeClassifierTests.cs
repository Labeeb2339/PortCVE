using System.Net;
using PortCVE.Analysis;
using PortCVE.Domain;

namespace PortCVE.Tests;

public sealed class BindScopeClassifierTests
{
    private static readonly NetworkInterfaceEvidence[] Interfaces =
    [
        new("loop", "Loopback", 1, "127.0.0.1", 8, "Unknown", true),
        new("wifi", "Wi-Fi", 7, "192.168.1.10", 24, "Private", true),
        new("down", "Ethernet", 8, "10.0.0.5", 24, "Public", false),
    ];

    [Fact]
    public void Classify_Loopback_IsHostOnly()
    {
        var result = BindScopeClassifier.Classify(IPAddress.Loopback, IpFamily.Ipv4, Interfaces);

        Assert.Equal(BindScope.Loopback, result.Scope);
        Assert.Equal("this machine only", result.Summary);
        Assert.Empty(result.ActiveOn);
    }

    [Fact]
    public void Classify_Wildcard_MapsOnlyUpMatchingFamilyInterfaces()
    {
        var result = BindScopeClassifier.Classify(IPAddress.Any, IpFamily.Ipv4, Interfaces);

        Assert.Equal(BindScope.Wildcard, result.Scope);
        Assert.Equal([1, 7], result.ActiveOn.Select(static item => item.Index));
    }

    [Fact]
    public void Classify_ExactAddress_MapsSpecificInterface()
    {
        var result = BindScopeClassifier.Classify(IPAddress.Parse("192.168.1.10"), IpFamily.Ipv4, Interfaces);

        Assert.Equal(BindScope.Interface, result.Scope);
        Assert.Single(result.ActiveOn);
        Assert.Equal("Wi-Fi", result.ActiveOn[0].Name);
    }
}
