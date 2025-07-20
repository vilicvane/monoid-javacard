param(
  [Parameter(Mandatory)]
	[string[]]$Commands
)

foreach ($command in $Commands) {
  Write-Host "Command: $command" -ForegroundColor Green

  # Create a new PowerShell process with the environment variable
  powershell.exe -Command "& { `$env:CARD_TYPE = 'physical'; & '.\gradlew.bat' test --info --rerun-tasks --tests 'MonoidAppletTest.$command' }"
}
