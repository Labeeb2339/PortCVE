[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TemplatePath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedSignerSubject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ExpectedSignerSubject) -or
    $ExpectedSignerSubject -ne $ExpectedSignerSubject.Trim() -or
    $ExpectedSignerSubject.Contains("`r") -or $ExpectedSignerSubject.Contains("`n")) {
    throw 'Expected signer subject is missing or malformed.'
}

$resolvedTemplate = (Resolve-Path -LiteralPath $TemplatePath -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $resolvedTemplate -PathType Leaf)) {
    throw "Installer template is not a file: $resolvedTemplate"
}
if (-not [StringComparer]::Ordinal.Equals([IO.Path]::GetFileName($resolvedTemplate), 'install.ps1')) {
    throw "Installer template must be named exactly 'install.ps1'."
}
if (-not [StringComparer]::Ordinal.Equals([IO.Path]::GetFileName($OutputPath), 'install.ps1')) {
    throw "Finalized installer must be named exactly 'install.ps1'."
}

$placeholder = '__PORTCVE_EXPECTED_SIGNER_SUBJECT__'
$installer = [IO.File]::ReadAllText($resolvedTemplate)
$placeholderCount = [regex]::Matches($installer, [regex]::Escape($placeholder)).Count
if ($placeholderCount -ne 1) {
    throw "Installer template must contain exactly one signer-subject placeholder; found $placeholderCount."
}

# The placeholder is inside a single-quoted PowerShell literal. Doubling an
# apostrophe is the only escaping needed for a literal single-quoted string.
$escapedSignerSubject = $ExpectedSignerSubject.Replace("'", "''")
$installer = $installer.Replace($placeholder, $escapedSignerSubject)
if ($installer.Contains($placeholder)) {
    throw 'Installer signer-subject placeholder replacement failed.'
}

$outputParent = Split-Path -Parent $OutputPath
if ([string]::IsNullOrWhiteSpace($outputParent)) {
    $outputParent = $PWD.Path
}
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    New-Item -ItemType Directory -Path $outputParent | Out-Null
}
$resolvedOutputParent = (Resolve-Path -LiteralPath $outputParent).Path
$resolvedOutput = Join-Path $resolvedOutputParent (Split-Path -Leaf $OutputPath)
if (Test-Path -LiteralPath $resolvedOutput) {
    throw "Refusing to overwrite existing finalized installer: $resolvedOutput"
}

# Windows PowerShell 5.1 treats BOM-less script files as the active ANSI code
# page. The BOM is required so non-ASCII X.500 subjects survive exact matching.
[IO.File]::WriteAllText($resolvedOutput, $installer, [Text.UTF8Encoding]::new($true))

$bytes = [IO.File]::ReadAllBytes($resolvedOutput)
if ($bytes.Length -lt 3 -or $bytes[0] -ne 0xef -or $bytes[1] -ne 0xbb -or $bytes[2] -ne 0xbf) {
    throw 'Finalized installer is not UTF-8 with BOM.'
}

$tokens = $null
$parseErrors = $null
$installerAst = [Management.Automation.Language.Parser]::ParseFile(
    $resolvedOutput,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "Finalized installer is not valid PowerShell: $($parseErrors.Message -join '; ')"
}

$subjectAssignments = @($installerAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        [StringComparer]::Ordinal.Equals($node.Left.Extent.Text, '$script:ExpectedSignerSubject')
}, $true))
if ($subjectAssignments.Count -ne 1 -or
    $subjectAssignments[0].Right -isnot [Management.Automation.Language.CommandExpressionAst] -or
    $subjectAssignments[0].Right.Expression -isnot [Management.Automation.Language.StringConstantExpressionAst] -or
    -not [StringComparer]::Ordinal.Equals(
        [string]$subjectAssignments[0].Right.Expression.Value,
        $ExpectedSignerSubject
    )) {
    throw 'Finalized installer does not evaluate to the exact expected signer subject.'
}

Get-Item -LiteralPath $resolvedOutput
