param([Parameter(Mandatory)][string]$Output)

$ErrorActionPreference = 'Stop'
$outputPath = (Resolve-Path -LiteralPath $Output).Path
$repositoryPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$attemptPath = Join-Path $outputPath 'build-attempt.json'

if (Test-Path -LiteralPath $attemptPath) {
  throw 'Build already attempted; freeze a new output directory'
}

node (Join-Path $PSScriptRoot 'prepare.mjs') check --output $outputPath
if ($LASTEXITCODE -ne 0) { throw 'Frozen inputs changed' }

$manifest = Get-Content -LiteralPath (Join-Path $outputPath 'manifest.json') -Raw | ConvertFrom-Json
@{state = 'started'; at = (Get-Date).ToUniversalTime().ToString('o')} |
  ConvertTo-Json | Set-Content -LiteralPath $attemptPath

$previousJavaHome = $env:JAVA_HOME
$buildLog = Join-Path $outputPath 'build.log'

try {
  $env:JAVA_HOME = Join-Path $repositoryPath '.jdk'
  & (Join-Path $repositoryPath 'gradlew.bat') --offline --no-daemon -p $outputPath buildJavaCard --console=plain *> $buildLog

  if ($LASTEXITCODE -ne 0) {
    Get-Content -LiteralPath $buildLog -Tail 45
    throw 'Build failed'
  }
} finally {
  $env:JAVA_HOME = $previousJavaHome
}

$buildText = Get-Content -LiteralPath $buildLog -Raw
$expected = $manifest.caps.Count
$verified = ($buildText | Select-String 'Verification passed' -AllMatches).Matches.Count
$converted = ($buildText | Select-String 'conversion completed with 0 errors and 0 warnings' -AllMatches).Matches.Count

if ($verified -ne $expected -or $converted -ne $expected) {
  throw "Require $expected verified zero-warning CAPs"
}

node (Join-Path $PSScriptRoot 'prepare.mjs') check --output $outputPath
if ($LASTEXITCODE -ne 0) { throw 'Frozen inputs changed' }

$artifacts = foreach ($entry in $manifest.caps) {
  $relativePath = "build/javacard/$($entry.name).cap"
  $instance = if ($entry.applet) { $entry.aid + '01' } else { $null }

  @{
    name = $entry.name
    aid = $entry.aid
    instance = $instance
    path = $relativePath
    sha256 = (Get-FileHash -LiteralPath (Join-Path $outputPath $relativePath) -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}

@{schemaVersion = 1; verified = $true; ref = $manifest.ref; suite = $manifest.suite; caps = @($artifacts)} |
  ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outputPath 'artifacts.json')

Write-Output "$expected isolated CAPs built and verified; no card access."
