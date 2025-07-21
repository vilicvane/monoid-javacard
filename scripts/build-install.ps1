param(
	[switch]$ReinstallSafe,
	[string[]]$RunCommands
)

.\gradlew.bat buildJavaCard;

gp.exe --uninstall build\javacard\monoid.cap;

if ($ReinstallSafe) {
	gp.exe --uninstall build\javacard\monoidsafe.cap;
}

if ($ReinstallSafe) {
	gp.exe --install build\javacard\monoidsafe.cap;
}

gp.exe --install build\javacard\monoid.cap;

if ($RunCommands) {
	.\scripts\run.ps1 -Commands $RunCommands
}
