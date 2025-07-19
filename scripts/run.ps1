param(
	[string[]]$Commands
)

$env:CARD_TYPE = "physical"

foreach ($command in $Commands) {
  Write-Host "Command: $command" -ForegroundColor Green
  .\gradlew.bat manualTest --info --rerun-tasks --tests "MonoidAppletTest.$command"
}
