param(
    [switch]$ReinstallStore
)

.\gradlew.bat buildJavaCard;

.\bin\gp.exe --uninstall .\applet\build\javacard\monoid.cap;

if ($ReinstallStore) {
    .\bin\gp.exe --uninstall .\applet\build\javacard\monoidstore.cap;
}

if ($ReinstallStore) {
    .\bin\gp.exe --install .\applet\build\javacard\monoidstore.cap;
}

.\bin\gp.exe --install .\applet\build\javacard\monoid.cap;
