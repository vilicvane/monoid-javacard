param(
	[ValidateSet('Install', 'ReinstallMonoid', 'ReinstallSafe')]
	[string]$Mode = 'ReinstallMonoid',
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

switch ($Mode) {
	'Install' {
		Invoke-GlobalPlatform --install build\javacard\monoidsafeidentity.cap;
		Invoke-GlobalPlatform --install build\javacard\monoidsafe.cap;
		Invoke-GlobalPlatform --install build\javacard\monoid.cap;
	}
	'ReinstallMonoid' {
		Invoke-GlobalPlatform --uninstall build\javacard\monoid.cap;
		Invoke-GlobalPlatform --install build\javacard\monoid.cap;
	}
	'ReinstallSafe' {
		Invoke-GlobalPlatform --uninstall build\javacard\monoid.cap;
		Invoke-GlobalPlatform --uninstall build\javacard\monoidsafe.cap;
		Invoke-GlobalPlatform --install build\javacard\monoidsafe.cap;
		Invoke-GlobalPlatform --install build\javacard\monoid.cap;
	}
}

if ($RunCommands) {
	.\scripts\run.ps1 -Commands $RunCommands
}
