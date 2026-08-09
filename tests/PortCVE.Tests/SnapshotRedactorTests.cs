using PortCVE.Domain;
using PortCVE.Output;

namespace PortCVE.Tests;

public sealed class SnapshotRedactorTests
{
    [Fact]
    public void Redact_RemovesAddressesPathsAccountsAndRuleDetailsFromJson()
    {
        var owner = new OwnerEvidence(
            4242,
            DateTimeOffset.Parse("2026-08-09T12:34:56Z"),
            "server.exe",
            "C:\\Users\\SecretUser\\server.exe",
            "deadbeef",
            123,
            "parent.exe",
            "S-1-5-21-SECRET",
            "SECRET-DOMAIN\\SecretUser",
            ["SecretService"],
            false,
            true,
            ["Secret limitation at C:\\Users\\SecretUser"]);
        var rule = new FirewallRuleEvidence(
            "secret-rule-id",
            "Secret office allow",
            "Allow",
            ["Private"],
            "TCP",
            "8080",
            "192.168.50.20",
            "10.20.30.0/24",
            "C:\\Users\\SecretUser\\server.exe",
            "SecretService",
            ["Rule 'Secret office allow' contains 10.20.30.0/24"]);
        var listener = new ListenerEvidence(
            "tcp/ipv4/192.168.50.20/8080",
            TransportProtocol.Tcp,
            IpFamily.Ipv4,
            "192.168.50.20",
            8080,
            "LISTEN",
            BindScope.Interface,
            "only interface 192.168.50.20",
            owner,
            [new("secret-adapter-id", "Office VPN", 9, "192.168.50.20", 24, "Private", true)],
            new(
                FirewallVerdict.Allow,
                Confidence.Medium,
                "Office VPN (Private): rule Secret office allow permits 10.20.30.0/24",
            [rule],
            ["Secret policy limitation"]),
            ["raw evidence 192.168.50.20"],
            ["listener limitation for SecretUser"],
            [
                new(
                    "docker",
                    "secret-container-id",
                    "secret-container-name",
                    "registry.internal/secret-image:latest",
                    "sha256:secret-image-id",
                    "192.168.50.20",
                    8080,
                    80,
                    TransportProtocol.Tcp,
                    Confidence.Medium,
                    ["secret container limitation"]),
            ]);
        var snapshot = new SystemSnapshot(
            1,
            "test",
            DateTimeOffset.UnixEpoch,
            1,
            "Windows",
            [],
            listener.ActiveOn,
            [listener],
            [new("interfaces", CollectorStatus.Partial, "test", "Secret diagnostic 192.168.50.20")]);

        var json = JsonOutput.Serialize(SnapshotRedactor.Redact(snapshot));

        Assert.DoesNotContain("192.168.50.20", json, StringComparison.Ordinal);
        Assert.DoesNotContain("10.20.30.0", json, StringComparison.Ordinal);
        Assert.DoesNotContain("SecretUser", json, StringComparison.Ordinal);
        Assert.DoesNotContain("SECRET-DOMAIN", json, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-rule-id", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Secret office allow", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Office VPN", json, StringComparison.Ordinal);
        Assert.DoesNotContain("4242", json, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-container", json, StringComparison.Ordinal);
        Assert.DoesNotContain("registry.internal", json, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-image-id", json, StringComparison.Ordinal);
        Assert.Contains("server.exe", json, StringComparison.Ordinal);
        Assert.Contains("redacted container", json, StringComparison.Ordinal);
    }
}
