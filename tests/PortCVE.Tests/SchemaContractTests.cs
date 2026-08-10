using System.Text.Json;
using PortCVE.Domain;
using PortCVE.Output;
using PortCVE.Remote;
using PortCVE.Remote.Advisories;
using PortCVE.Remote.Imports;
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
    public void WeakOwnerPolicyLockfileShapeMatchesPublishedSchema()
    {
        var snapshot = Snapshot();
        var listener = snapshot.Listeners[0] with
        {
            Owner = snapshot.Listeners[0].Owner with { ImageSha256 = null },
            ContainerExposures = [],
        };
        var lockfile = new LockfileService().Create(
            snapshot with { Listeners = [listener] },
            includesHostPolicy: true,
            allowWeakOwner: true);
        var json = JsonOutput.Serialize(lockfile);

        Assert.Equal(OwnerIdentityStrength.NameOnly, Assert.Single(lockfile.Listeners).OwnerIdentityStrength);
        Assert.Equal(EvidenceCompleteness.Partial, lockfile.Evidence.Ownership);
        Assert.True(lockfile.IsComplete);
        Assert.Contains("\"allow_weak_owner\": true", json, StringComparison.Ordinal);
        AssertSerializedShape(json, "portcve.lock.v1.schema.json");
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

    [Fact]
    public async Task ScanAllMixedHostPrivateAndRedactedShapesMatchPublishedSchema()
    {
        var imageId = $"sha256:{new string('a', 64)}";
        var report = await new VulnerabilityAssessmentService(
            new VulnerabilityAssessmentTests.FixedScanner(
                VulnerabilityAssessmentTests.CompleteResult(VulnerabilitySeverity.Medium))).AssessAsync(
            "test",
            "all_tcp_listeners",
            [
                VulnerabilityAssessmentTests.Listener(8080, imageId, "web", "example/web:1"),
                VulnerabilityAssessmentTests.Listener(9000, null, null, null),
            ],
            null,
            VulnerabilitySelectionMode.AllScanCapableSubjects,
            CancellationToken.None);

        Assert.True(report.Summary.IsComplete);
        AssertSerializedShape(
            JsonOutput.Serialize(report),
            "portcve.vulnerability.v1.schema.json");
        AssertSerializedShape(
            JsonOutput.Serialize(VulnerabilityReportRedactor.Redact(report)),
            "portcve.vulnerability.v1.schema.json");
    }

    [Fact]
    public void PrivateAndReducedDatabaseDocumentsMatchPublishedSchema()
    {
        var status = new TrivyDatabaseStatus(
            TrivyDatabaseDocument.CurrentSchemaVersion,
            "trivy",
            TrivyDatabaseOperation.Status,
            TrivyDatabaseState.Ready,
            true,
            false,
            "C:\\Tools\\trivy.exe",
            "0.73.0",
            "C:\\Cache\\trivy",
            2,
            DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch.AddHours(6),
            60,
            (long)TimeSpan.FromHours(72).TotalSeconds,
            5,
            "ok",
            "The local Trivy vulnerability database is ready.");
        var privateDocument = TrivyDatabaseDocument.FromStatus(status, "test");

        AssertSerializedShape(
            JsonOutput.Serialize(privateDocument),
            "portcve.database.v1.schema.json");
        AssertSerializedShape(
            JsonOutput.Serialize(TrivyDatabaseDocumentRedactor.Redact(privateDocument)),
            "portcve.database.v1.schema.json");
    }

    [Fact]
    public void DatabaseSchemaIdentityAndReleasePackagingAreStable()
    {
        var root = RepositoryRoot();
        using var schema = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(root, "schema", "portcve.database.v1.schema.json")));

        Assert.Equal(
            "https://json-schema.org/draft/2020-12/schema",
            schema.RootElement.GetProperty("$schema").GetString());
        Assert.Equal(
            "urn:portcve:schema:database:v1",
            schema.RootElement.GetProperty("$id").GetString());
        Assert.Equal(1,
            schema.RootElement.GetProperty("properties").GetProperty("schema_version").GetProperty("const").GetInt32());

        var releaseWorkflow = File.ReadAllText(Path.Combine(root, ".github", "workflows", "release.yml"));
        Assert.Matches(
            @"(?m)Copy-Item\s+-LiteralPath\s+schema\s+-Destination\s+.+\s+-Recurse\s*$",
            releaseWorkflow);
    }

    [Fact]
    public void ExternalEvidenceImportShapeMatchesPublishedSchema()
    {
        var document = new PentestImportDocument(
            PentestImportDocument.CurrentSchemaVersion,
            "test",
            DateTimeOffset.UnixEpoch,
            new("fixture.xml", 123, new string('a', 64)),
            "nmap_xml",
            "7.98",
            true,
            [
                new(
                    "192.0.2.10",
                    "fixture.example",
                    "tcp",
                    443,
                    "open",
                    "syn-ack",
                    new(
                        "https",
                        "fixture",
                        "1.0",
                        "test service",
                        ["cpe:/a:fixture:service:1.0"],
                        ImportedEvidenceStrength.Strong,
                        "nmap_service_probe")),
            ],
            [
                new(
                    "nmap_nse",
                    "fixture-check",
                    "Imported Nmap NSE observation: fixture-check",
                    "unknown",
                    "192.0.2.10",
                    443,
                    "tcp",
                    ImportedClaimStatus.ImportedMatch,
                    ImportedEvidenceStrength.Unresolved,
                    [],
                    [],
                    new string('b', 64),
                    "fixture-check",
                    "External observation"),
            ],
            [new("fixture_diagnostic", "Fixture diagnostic.")]);

        AssertSerializedShape(
            JsonOutput.Serialize(document),
            "portcve.import.v1.schema.json");
    }

    [Fact]
    public void PrivateAndRedactedRemoteReportShapesMatchPublishedSchema()
    {
        var report = RemoteReportFixture();

        AssertSerializedShape(
            JsonOutput.Serialize(report),
            "portcve.remote.v1.schema.json");
        AssertSerializedShape(
            JsonOutput.Serialize(RemoteAuditRedactor.Redact(report)),
            "portcve.remote.v1.schema.json");
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
            if (!schema.TryGetProperty("properties", out var properties))
            {
                Assert.True(
                    schema.TryGetProperty("additionalProperties", out var additionalProperties)
                    && additionalProperties.ValueKind == JsonValueKind.Object,
                    $"{schemaFile}: schema node for {path} has neither properties nor an additionalProperties schema.");
                foreach (var property in instance.EnumerateObject())
                {
                    AssertShape(
                        property.Value,
                        additionalProperties,
                        schemaRoot,
                        $"{path}.{property.Name}",
                        schemaFile);
                }

                return;
            }

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

    private static RemoteAuditReport RemoteReportFixture()
    {
        var fingerprint = new RemoteFingerprint(
            RemoteFingerprintKind.Ssh,
            "ssh",
            RemoteFingerprintConfidence.ProtocolConfirmed,
            "passive-greeting",
            "SSH-2.0-OpenSSH_9.6p1",
            RemoteFingerprint.ReadOnlyAttributes(new Dictionary<string, string>
            {
                ["protocolVersion"] = "2.0",
            }));
        var product = new RemoteProductCandidate(
            "OpenSSH",
            "9.6p1",
            RemoteProductConfidence.BannerPattern,
            "passive-greeting",
            "OpenSSH_9.6p1");
        var host = new RemoteHostReport(
            "fixture.example",
            ["192.0.2.10"],
            [new("192.0.2.10", "ipv4", 22, RemotePortState.Open, 1, [fingerprint], [product], [])],
            []);
        var cpe = "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*";
        var applicability = new RemoteAdvisoryApplicability(
            RemoteAdvisoryApplicabilityDisposition.DirectCandidate,
            true,
            false,
            [
                new(
                    "OR",
                    false,
                    [
                        new(
                            "OR",
                            false,
                            [new(
                                true,
                                cpe,
                                "00000000-0000-0000-0000-000000000001",
                                null,
                                null,
                                null,
                                null,
                                RemoteAdvisoryCpeAlignment.Proven,
                                true,
                                false)]),
                    ]),
            ],
            []);
        var match = new RemoteAdvisoryMatch(
            "CVE-2026-0001",
            "candidate",
            "remote_banner_match",
            "OpenSSH",
            "9.6p1",
            cpe,
            "OpenSSH_9.6p1",
            RemoteAdvisoryConfidence.Strong,
            "Analyzed",
            DateTimeOffset.UnixEpoch,
            applicability,
            RemoteAdvisorySeverity.High,
            "nvd@nist.gov/CVSS:3.1",
            "Fixture candidate advisory.",
            ["https://example.invalid/CVE-2026-0001"],
            false,
            "not_assessed");
        var assessment = new RemoteAdvisoryAssessment(
            "remote-product-0001",
            "fixture.example",
            "192.0.2.10",
            22,
            "OpenSSH",
            "9.6p1",
            RemoteProductConfidence.BannerPattern,
            "OpenSSH_9.6p1",
            RemoteIdentityDisposition.Resolved,
            cpe,
            "NVD Official CPE Dictionary (CPE API 2.0)",
            "remote-advisory-result-0001",
            []);
        var providerResult = new RemoteAdvisoryProviderResult(
            "remote-advisory-result-0001",
            "OpenSSH",
            "9.6p1",
            cpe,
            "NVD Official CPE Dictionary (CPE API 2.0)",
            RemoteAdvisoryStatus.Complete,
            RemoteAdvisoryResult.ProviderName,
            RemoteAdvisoryResult.ExplicitOnlineNetworkMode,
            DateTimeOffset.UnixEpoch,
            [match],
            []);
        return new(
            1,
            "test",
            DateTimeOffset.UnixEpoch,
            "fixture.example",
            "tcp",
            "discovery",
            true,
            true,
            RemoteAdvisoryStatus.Complete,
            RemoteAuditService.MaximumUniqueAdvisoryIdentities,
            [22],
            [host],
            [assessment],
            [providerResult],
            new(1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, true),
            [],
            RemoteAuditService.ClaimBoundary,
            RemoteAuditService.NvdNotice);
    }
}
