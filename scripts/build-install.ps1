param(
	[ValidateSet('Install', 'ReinstallMonoid')]
	[string]$Mode = 'Install',
	[ValidatePattern('^[0-9A-Fa-f]{8}$')]
	[string]$CardId,
	[ValidatePattern('^04[0-9A-Fa-f]{128}$')]
	[string]$AuthorityPublicKey,
	[ValidateNotNullOrEmpty()]
	[string]$AuthorityUrl,
	[string[]]$RunCommands
)

$ErrorActionPreference = 'Stop';

if ($Mode -ne 'Install' -and ($CardId -or $AuthorityPublicKey -or $AuthorityUrl)) {
	throw 'CardId, AuthorityPublicKey and AuthorityUrl apply only when installing Monoid Identity.';
}

if ([bool]$AuthorityPublicKey -ne [bool]$AuthorityUrl) {
	throw 'AuthorityPublicKey and AuthorityUrl must be provided together.';
}

$identityInstallArguments = @('--install', 'build\javacard\monoididentity.cap');
$flags = 0;

if ($CardId) {
	$flags = $flags -bor 0x01;
}

$authorityUrlHex = '';

if ($AuthorityPublicKey) {
	$flags = $flags -bor 0x02;
	$authorityUrlBytes = [System.Text.Encoding]::UTF8.GetBytes($AuthorityUrl);
	$authorityUrlHex = [System.BitConverter]::ToString($authorityUrlBytes).Replace('-', '');
}

if ($flags) {
	$parameters = '{0:X2}{1}{2}{3}' -f $flags, $CardId, $AuthorityPublicKey, $authorityUrlHex;

	# The install buffer includes the 9-byte instance AID and three length bytes.
	if (12 + $parameters.Length / 2 -gt 255) {
		throw 'Identity installation data exceeds the 255-byte install buffer.';
	}

	$identityInstallArguments += @('--params', $parameters);
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
