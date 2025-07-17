param(
    [switch]$ReinstallSafe
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
