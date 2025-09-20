param([string[]]$Commands=@())

if (-not $Commands -or $Commands.Count -eq 0) {
  # No specific commands provided: run full test suite (no --tests filter)
  powershell.exe -Command "& { `$env:CARD_TYPE = 'physical'; & '.\gradlew.bat' test --info --rerun-tasks }"
} else {
  foreach ($command in $Commands) {
    Write-Host "Command: $command" -ForegroundColor Green

    # Create a new PowerShell process with the environment variable
    powershell.exe -Command "& { `$env:CARD_TYPE = 'physical'; & '.\gradlew.bat' test --info --rerun-tasks --tests 'MonoidAppletTest.$command' }"
  }
}
