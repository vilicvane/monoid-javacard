param(
	[switch]$ReinstallSafe,
	[string[]]$RunCommands
)

.\gradlew.bat buildJavaCard;

.\bin\gp.exe --uninstall .\applet\build\javacard\monoid.cap;

if ($ReinstallSafe) {
	.\bin\gp.exe --uninstall .\applet\build\javacard\monoidsafe.cap;
}

if ($ReinstallSafe) {
	.\bin\gp.exe --install .\applet\build\javacard\monoidsafe.cap;
}

.\bin\gp.exe --install .\applet\build\javacard\monoid.cap;

if ($RunCommands) {
	.\scripts\run.ps1 -Commands $RunCommands
}
