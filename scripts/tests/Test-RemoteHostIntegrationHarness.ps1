#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$harnessPath = Join-Path $repositoryRoot 'scripts\Test-RemoteHostIntegration.ps1'
$source = [IO.File]::ReadAllText($harnessPath)
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    throw "Remote integration harness has PowerShell syntax errors: $($parseErrors.Message -join '; ')"
}

$script:Passed = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:Passed++
}

$parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
Assert-True ($parameterNames -ccontains 'PortCVEPath') 'Harness does not expose the expected executable override.'
Assert-True ($parameterNames -cnotcontains 'Target') 'Harness must not accept an arbitrary network target.'
Assert-True ($parameterNames -cnotcontains 'Host') 'Harness must not accept an arbitrary network host.'
Assert-True ($parameterNames -cnotcontains 'Address') 'Harness must not accept an arbitrary network address.'

$commands = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $null -ne $_ })
foreach ($forbidden in @(
        'Invoke-WebRequest', 'Invoke-RestMethod', 'curl', 'curl.exe', 'wget',
        'nmap', 'nmap.exe', 'Test-NetConnection', 'Invoke-Expression')) {
    Assert-True ($commands -cnotcontains $forbidden) "Harness invokes forbidden command '$forbidden'."
}

Assert-True ($source.Contains("`$loopbackTarget = '127.0.0.1'")) 'Harness does not freeze its CLI target to IPv4 loopback.'
$ephemeralLoopbackListeners = [regex]::Matches(
    $source,
    [regex]::Escape('new TcpListener(IPAddress.Loopback, 0)'))
Assert-True ($ephemeralLoopbackListeners.Count -eq 2) 'Both fixtures must use distinct OS-assigned loopback ports.'
Assert-True ($source.Contains('public static LoopbackFixture StartHttp()')) 'HTTP fixture does not use an OS-assigned port.'
Assert-True (-not $source.Contains('candidatePorts')) 'Harness still exposes a configured HTTP-port candidate list.'
Assert-True ($source.Contains("'scan-host', `$loopbackTarget")) 'Harness does not exercise the scan-host CLI path.'
Assert-True ($source.Contains("'--authorized'")) 'Harness does not make the authorization assertion explicit.'
Assert-True ($source.Contains("@('--active', '--include-private')")) 'Harness does not exercise private safe-active mode.'
Assert-True (-not $source.Contains("'--online-advisories'")) 'Harness must not make an online advisory request.'
Assert-True ($source.Contains("`$method -in @('HEAD', 'OPTIONS')")) 'Harness does not enforce the safe HTTP method allowlist.'
Assert-True ($source.Contains("-ExpectedRequests @{ 'HEAD /' = 1 }")) 'Harness does not assert the one-request adaptive HTTP boundary.'
Assert-True ($source.Contains("'active-adaptive-http-head'")) 'Harness does not assert the adaptive HTTP evidence source.'
Assert-True ($source.Contains('finally {')) 'Harness does not contain guarded cleanup.'
Assert-True ($source.Contains('Remove-Item -LiteralPath $resolvedTemporaryDirectory -Recurse -Force')) 'Harness does not use the guarded resolved cleanup target.'
Assert-True ($source.Contains('$process.Kill()')) 'Harness does not terminate bounded child processes on timeout or cleanup.'
Assert-True ($source.Contains('[Diagnostics.Process]::new()')) 'Harness does not own its child process handle directly.'
Assert-True ($source.Contains('$fixture.Stop()')) 'Harness does not stop its listener fixtures explicitly.'

Write-Output "Remote host integration harness checks passed: $script:Passed"
