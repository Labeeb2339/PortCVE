using System.Text.Json;
using PortCVE.Domain;
using PortCVE.Output;
using PortCVE.Snapshots;
using PortCVE.Vulnerabilities;

namespace PortCVE.Tests;

public sealed class SchemaContractTests
{
    [Fact]
    public void GeneratedLockfileShapeMatchesPublishedSchema()
    {
        var snapshot = Snapshot();
        var lockfile = new LockfileService().Create(
            snapshot,
            includesUdp: false,
            includesHostPolicy: true,
            selector: new(8080, TransportProtocol.Tcp, null, null),
            includesContainerEvidence: true);

        AssertSerializedShape(
            JsonOutput.Serialize(lockfile),
            "portcve.lock.v1.schema.json");
    }

    [Fact]
    public void PrivateAndRedactedSnapshotShapesMatchPublishedSchema()
    {
        var snapshot = Snapshot();

        AssertSerializedShape(
            JsonOutput.Serialize(snapshot),
            "portcve.snapshot.v1.schema.json");
        AssertSerializedShape(
            JsonOutput.Serialize(SnapshotRedactor.Redact(snapshot)),
            "portcve.snapshot.v1.schema.json");
    }

    [Fact]
    public void PrivateAndRedactedVulnerabilityReportShapesMatchPublishedSchema()
    {
        var report = VulnerabilityReportFixture();

        AssertSerializedShape(
            JsonOutput.Serialize(report),
            "portcve.vulnerability.v1.schema.json");
        AssertSerializedShape(
            JsonOutput.Serialize(VulnerabilityReportRedactor.Redact(report)),
            "portcve.vulnerability.v1.schema.json");
    }

    private static void AssertSerializedShape(string json, string schemaFile)
    {
        using var instance = JsonDocument.Parse(json);
        using var schema = JsonDocument.Parse(File.ReadAllText(Path.Combine(RepositoryRoot(), "schema", schemaFile)));

        AssertShape(instance.RootElement, schema.RootElement, schema.RootElement, "$", schemaFile);
    }

    private static void AssertShape(
        JsonElement instance,
        JsonElement schema,
        JsonElement schemaRoot,
        string path,
        string schemaFile)
    {
        schema = ResolveReference(schema, schemaRoot);
        if (instance.ValueKind == JsonValueKind.Object)
        {
            Assert.True(
                schema.TryGetProperty("properties", out var properties),
                $"{schemaFile}: schema node for {path} has no properties object.");

            if (schema.TryGetProperty("required", out var required))
            {
                foreach (var requiredName in required.EnumerateArray().Select(static item => item.GetString()!))
                {
                    Assert.True(
                        instance.TryGetProperty(requiredName, out _),
                        $"{schemaFile}: generated {path} is missing required property '{requiredName}'.");
                }
            }

            foreach (var property in instance.EnumerateObject())
            {
                Assert.True(
                    properties.TryGetProperty(property.Name, out var propertySchema),
                    $"{schemaFile}: generated property '{path}.{property.Name}' is absent from the schema.");
                AssertShape(property.Value, propertySchema, schemaRoot, $"{path}.{property.Name}", schemaFile);
            }

            return;
        }

        if (instance.ValueKind == JsonValueKind.Array && schema.TryGetProperty("items", out var itemSchema))
        {
            var index = 0;
            foreach (var item in instance.EnumerateArray())
            {
                AssertShape(item, itemSchema, schemaRoot, $"{path}[{index++}]", schemaFile);
            }
        }
    }

    private static JsonElement ResolveReference(JsonElement schema, JsonElement schemaRoot)
    {
        while (schema.TryGetProperty("$ref", out var reference))
        {
            var value = reference.GetString();
            Assert.NotNull(value);
            Assert.StartsWith("#/", value, StringComparison.Ordinal);
            schema = schemaRoot;
            foreach (var segment in value[2..].Split('/'))
            {
                var property = segment.Replace("~1", "/", StringComparison.Ordinal)
                    .Replace("~0", "~", StringComparison.Ordinal);
                Assert.True(schema.TryGetProperty(property, out schema), $"Schema reference '{value}' is invalid.");
            }
        }

        return schema;
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "PortCVE.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException("Could not locate the PortCVE repository root.");
    }

    private static SystemSnapshot Snapshot()
    {
        var networkInterface = new NetworkInterfaceEvidence(
            "adapter-id",
            "Wi-Fi",
            7,
            "192.168.1.10",
            24,
            "Private",
            true);
        var owner = new OwnerEvidence(
            100,
            DateTimeOffset.UnixEpoch,
            "server.exe",
            "C:\\Apps\\server.exe",
            new string('a', 64),
            50,
            "parent.exe",
            "S-1-5-18",
            "NT AUTHORITY\\SYSTEM",
            [],
            false,
            true,
            []);
        var rule = new FirewallRuleEvidence(
            "rule-id",
            "Allow server",
            "Allow",
            ["Private"],
            "TCP",
            "8080",
            "Any",
            "Any",
            "C:\\Apps\\server.exe",
            "Any",
            []);
        var container = new ContainerExposureEvidence(
            "docker",
            "container-id",
            "web",
            "example/web:1.0",
            $"sha256:{new string('b', 64)}",
            "0.0.0.0",
            8080,
            80,
            TransportProtocol.Tcp,
            Confidence.Medium,
            ["Docker publication was correlated by host tuple."]);
        var listener = new ListenerEvidence(
            "tcp/ipv4/0.0.0.0/8080",
            TransportProtocol.Tcp,
            IpFamily.Ipv4,
            "0.0.0.0",
            8080,
            "LISTEN",
            BindScope.Wildcard,
            "all IPv4 interfaces",
            owner,
            [networkInterface],
            new(
                FirewallVerdict.Allow,
                Confidence.Medium,
                "Static host policy indicates allow.",
            [rule],
            ["External path was not tested."]),
            ["Native endpoint evidence."],
            [],
            [container]);
        return new(
            1,
            "test",
            DateTimeOffset.UnixEpoch,
            1,
            "Windows",
            [
                new("sockets", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
                new("docker", CollectorStatus.Complete, DateTimeOffset.UnixEpoch, 1, []),
            ],
            [networkInterface],
            [listener],
            []);
    }

    private static VulnerabilityReport VulnerabilityReportFixture()
    {
        var diagnostic = new VulnerabilityDiagnostic(
            "trivy",
            VulnerabilityProviderStatus.Partial,
            "vulnerability_db_stale",
            "Fixture database is stale.");
        return new(
            1,
            "test",
            DateTimeOffset.UnixEpoch,
            "tcp:8080",
            [
                new(
                    "subject-001",
                    VulnerabilitySubjectKind.ContainerImage,
                    "example/web:1",
                    $"sha256:{new string('a', 64)}",
                    new string('a', 64),
                    VulnerabilityIdentityConfidence.Exact,
                    [
                        new(
                            "tcp/ipv4/0.0.0.0/8080",
                            TransportProtocol.Tcp,
                            IpFamily.Ipv4,
                            BindScope.Wildcard,
                            8080),
                    ],
                    VulnerabilityScanStatus.Partial,
                    ["Fixture limitation."]),
            ],
            [
                new(
                    "trivy",
                    "0.66.0",
                    DateTimeOffset.UnixEpoch,
                    1,
                    "offline",
                    VulnerabilityProviderStatus.Partial,
                    5,
                    [diagnostic]),
            ],
            [
                new(
                    "finding-0001",
                    "subject-001",
                    "known_advisory_match",
                    "CVE-2026-0001",
                    ["VENDOR-1"],
                    new("alpine", "busybox", "1.0", ["1.1"]),
                    "vendor_package_version",
                    VulnerabilityIdentityConfidence.Exact,
                    VulnerabilitySeverity.High,
                    "vendor",
                    VulnerabilityFixState.FixedVersionAvailable,
                    "not_assessed",
                    "not_assessed",
                    "Fixture advisory",
                    "https://example.invalid/CVE-2026-0001",
                    ["https://example.invalid/reference"]),
            ],
            new(1, 1, 0, 1, 0, 1, false),
            [diagnostic]);
    }
}
