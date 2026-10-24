param(
	[string]$Reader
)

$ErrorActionPreference = 'Stop';

$readerArguments = @();

if ($Reader) {
	$readerArguments = @('--reader', $Reader);
}

function Invoke-GlobalPlatform {
	gp.exe @readerArguments @args;

	if ($LASTEXITCODE -ne 0) {
		throw "GlobalPlatform failed with exit code $LASTEXITCODE ($args).";
	}
}

$packageAIDs = @(
	# @inplate-line '{{hex MONOID_OTP_PACKAGE_AID uppercase=true}}',
	'F06D6F6E6F696405',
	# @inplate-line '{{hex MONOID_SECURITY_KEY_PACKAGE_AID uppercase=true}}',
	'F06D6F6E6F696403',
	# @inplate-line '{{hex MONOID_PACKAGE_AID uppercase=true}}',
	'F06D6F6E6F696402',
	# @inplate-line '{{hex MONOID_LIB_PACKAGE_AID uppercase=true}}',
	'F06D6F6E6F696404',
	# @inplate-line '{{hex MONOID_IDENTITY_PACKAGE_AID uppercase=true}}'
	'F06D6F6E6F696400'
);

$registry = @(Invoke-GlobalPlatform --list);
$installedPackages = @();
$applets = @();
$applet = $null;

foreach ($line in $registry) {
	if ($line -match '^(\w+):\s+([0-9a-f]+)(?:\s|$)') {
		$applet = $null;

		switch ($Matches[1]) {
			'APP' {
				$applet = @{ AID = $Matches[2]; PackageAID = $null };
				$applets += $applet;
			}
			'PKG' {
				$installedPackages += $Matches[2];
			}
		}
	} elseif ($applet -and $line -match '^\s+From:\s+([0-9a-f]+)\s*$') {
		$applet.PackageAID = $Matches[1];
	}
}

foreach ($packageAID in $packageAIDs) {
	foreach ($applet in $applets) {
		if ($applet.PackageAID -eq $packageAID) {
			Write-Host "Deleting applet $($applet.AID)...";
			Invoke-GlobalPlatform --delete $applet.AID;
		}
	}

	if ($installedPackages -contains $packageAID) {
		Write-Host "Deleting package $packageAID...";
		Invoke-GlobalPlatform --delete $packageAID;
	}
}
