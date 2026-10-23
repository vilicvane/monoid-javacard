param(
	[ValidateSet('Install', 'ReinstallMonoid')]
	[string]$Mode = 'Install',
	[ValidatePattern('^[0-9A-Fa-f]{8}$')]
	[string]$CardId,
	[ValidatePattern('^04[0-9A-Fa-f]{128}$')]
	[string]$AuthorityPublicKey,
	[string[]]$RunCommands
)

$ErrorActionPreference = 'Stop';

if ($Mode -ne 'Install' -and ($CardId -or $AuthorityPublicKey)) {
	throw 'CardId and AuthorityPublicKey apply only when installing Monoid Identity.';
}

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
		$identityInstallArguments = @('--install', 'build\javacard\monoididentity.cap');
		$flags = 0;

		if ($CardId) {
			$flags = $flags -bor 0x01;
		}

		if ($AuthorityPublicKey) {
			$flags = $flags -bor 0x02;
		}

		if ($flags) {
			$parameters = '{0:X2}{1}{2}' -f $flags, $CardId, $AuthorityPublicKey;
			$identityInstallArguments += @('--params', $parameters);
		}

		Invoke-GlobalPlatform @identityInstallArguments;
		Invoke-GlobalPlatform --load build\javacard\monoidlib.cap;
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
