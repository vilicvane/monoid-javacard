param(
	[switch]$InstallIdentity,
	[switch]$ReinstallSafe,
	[string[]]$RunCommands
)

$ErrorActionPreference = 'Stop';

function Invoke-GlobalPlatform {
	gp.exe @args;

	if ($LASTEXITCODE -ne 0) {
		throw "GlobalPlatform failed with exit code $LASTEXITCODE.";
	}
}

.\gradlew.bat buildJavaCard;

if ($LASTEXITCODE -ne 0) {
	throw "Java Card build failed with exit code $LASTEXITCODE.";
}

if (-not $InstallIdentity) {
	Invoke-GlobalPlatform --uninstall build\javacard\monoid.cap;

	if ($ReinstallSafe) {
		Invoke-GlobalPlatform --uninstall build\javacard\monoidsafe.cap;
	}
}

if ($InstallIdentity) {
	Invoke-GlobalPlatform --install build\javacard\monoidsafeidentity.cap;
}

if ($InstallIdentity -or $ReinstallSafe) {
	Invoke-GlobalPlatform --install build\javacard\monoidsafe.cap;
}

Invoke-GlobalPlatform --install build\javacard\monoid.cap;

if ($RunCommands) {
	.\scripts\run.ps1 -Commands $RunCommands
}
