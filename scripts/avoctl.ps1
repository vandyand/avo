[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $AvoArguments
)

$ErrorActionPreference = "Stop"
$projectPath = $env:AVO_WSL_PROJECT_PATH
if ([string]::IsNullOrWhiteSpace($projectPath)) {
    Write-Error "AVO_WSL_PROJECT_PATH is not set. Set it to the WSL path of this repository."
    exit 2
}
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    Write-Error "wsl.exe was not found. Install WSL 2 first."
    exit 2
}
& wsl.exe --cd $projectPath --exec test -x .venv/bin/avoctl
if ($LASTEXITCODE -eq 0) {
    & wsl.exe --cd $projectPath --exec .venv/bin/avoctl @AvoArguments
}
else {
    & wsl.exe --cd $projectPath --exec uv run avoctl @AvoArguments
}
exit $LASTEXITCODE
