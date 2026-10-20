param(
	[ValidateSet('Install', 'ReinstallMonoid')]
	[string]$Mode = 'Install',
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
		Invoke-GlobalPlatform --install build\javacard\monoididentity.cap;
		Invoke-GlobalPlatform --install build\javacard\monoid.cap;
	}
	'ReinstallMonoid' {
		Write-Host 'Reinstalling Monoid clears all stored Safe items and the Access PIN. Monoid Identity and its Secret PIN are preserved.';
		Invoke-GlobalPlatform --uninstall build\javacard\monoid.cap;
		Invoke-GlobalPlatform --install build\javacard\monoid.cap;
	}
}

if ($RunCommands) {
	.\scripts\run.ps1 -Commands $RunCommands
}
