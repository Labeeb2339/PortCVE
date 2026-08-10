#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$harnessPath = Join-Path $repositoryRoot 'scripts\Test-ExposureVerificationIntegration.ps1'
$source = [IO.File]::ReadAllText($harnessPath)
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    throw "Exposure verification harness has PowerShell syntax errors: $($parseErrors.Message -join '; ')"
}

$script:Passed = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:Passed++
}

$parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
Assert-True ($parameterNames -ccontains 'PortCVEPath') `
    'Harness does not expose the expected executable override.'
foreach ($forbiddenParameter in @('Target', 'Host', 'Address', 'Port')) {
    Assert-True ($parameterNames -cnotcontains $forbiddenParameter) `
        "Harness must not accept arbitrary network parameter '$forbiddenParameter'."
}

$commands = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $null -ne $_ })
foreach ($forbiddenCommand in @(
        'Invoke-WebRequest', 'Invoke-RestMethod', 'Invoke-Expression',
        'curl', 'curl.exe', 'wget', 'nmap', 'nmap.exe', 'Test-NetConnection')) {
    Assert-True ($commands -cnotcontains $forbiddenCommand) `
        "Harness invokes forbidden network command '$forbiddenCommand'."
}

Assert-True ($source.Contains("`$syntheticTarget = '192.0.2.10'")) `
    'Harness does not freeze its imported identity to the TEST-NET fixture address.'
Assert-True ($source.Contains('new TcpListener(IPAddress.Any, 0)')) `
    'Harness does not use one OS-assigned IPv4 wildcard listener.'
Assert-True ($source.Contains("'verify', `$nmapPath")) `
    'Harness does not exercise the offline verify command.'
Assert-True (-not $source.Contains("'scan-host'")) `
    'Harness must not exercise a network scanning command.'
Assert-True (-not $source.Contains("'--authorized'")) `
    'Offline verification must not carry a remote-scan authorization flag.'
Assert-True (-not $source.Contains("'--online-advisories'")) `
    'Harness must not enable online advisory traffic.'
Assert-True ($source.Contains("'--nuclei', `$nucleiPath")) `
    'Harness does not import Nuclei provenance.'
Assert-True ($source.Contains("'--nessus', `$nessusPath")) `
    'Harness does not import Nessus provenance.'
Assert-True ($source.Contains("'--no-firewall'")) `
    'Harness does not isolate verification from host firewall policy collection.'
Assert-True ($source.Contains("'--strict'")) `
    'Harness does not assert complete evidence with strict mode.'
Assert-True ($source.Contains("@(`$baseArguments + '--include-private')")) `
    'Harness does not exercise private output.'
Assert-True ($source.Contains('did not deduplicate the shared CVE into one finding group')) `
    'Harness does not assert CVE grouping.'
Assert-True ($source.Contains("`$sources -ccontains 'nuclei_jsonl'")) `
    'Harness does not assert Nuclei source provenance.'
Assert-True ($source.Contains("`$sources -ccontains 'nessus_xml'")) `
    'Harness does not assert Nessus source provenance.'
Assert-True ($source.Contains("-not `$defaultCapture.StdOut.Contains(`$syntheticTarget)")) `
    'Harness does not assert default target redaction.'
Assert-True ($source.Contains("`$privateReport.association.imported_target -ceq `$syntheticTarget")) `
    'Harness does not assert private target retention.'
Assert-True ($source.Contains("`$defaultReport.privacy_mode -ceq 'reduced'")) `
    'Harness does not assert reduced default output.'
Assert-True ($source.Contains("`$privateReport.privacy_mode -ceq 'private'")) `
    'Harness does not assert explicit private output.'
Assert-True ($source.Contains("-not `$listener.HasPendingConnection")) `
    'Harness does not assert that verify left the local listener untouched.'
Assert-True ($source.Contains("'--no-restore'")) `
    'Harness build could attempt dependency restoration or network access.'
Assert-True ($source.Contains('64KB')) `
    'Harness does not bound its synthetic input files.'
Assert-True ($source.Contains('$process.WaitForExit($TimeoutSeconds * 1000)')) `
    'Harness child processes are not time-bounded.'
Assert-True ($source.Contains('$process.Kill()')) `
    'Harness does not terminate a child process after its bound.'
Assert-True ($source.Contains('finally {')) `
    'Harness does not contain guarded cleanup.'
Assert-True ($source.Contains('$listener.Stop()')) `
    'Harness does not stop its local fixture.'
Assert-True ($source.Contains('Remove-Item -LiteralPath $resolvedTemporaryDirectory -Recurse -Force')) `
    'Harness does not use its validated cleanup target.'

Write-Output "Exposure verification harness checks passed: $script:Passed"
