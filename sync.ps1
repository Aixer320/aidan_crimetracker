param(
  [string]$Message
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Move to repository root (this script should be placed at repo root)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Verify we're in a Git repo
$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $?) {
  Write-Error "Not inside a Git repository."
  exit 1
}
Set-Location $repoRoot

# Determine current branch
$branch = (git rev-parse --abbrev-ref HEAD).Trim()
if (-not $branch) {
  Write-Error "Unable to determine current branch."
  exit 1
}

# Stage all changes
Write-Host "Staging changes..."
git add -A | Out-Null

# Default commit message (timestamped) if none provided
if (-not $Message) {
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm")
  $Message = "chore: SYNC at $ts"
}

# Commit only if there are staged changes
# Note: exit code 0 => no changes; non-zero => changes
& git diff --cached --quiet
$hasStaged = -not $?
if ($hasStaged) {
  Write-Host "Committing changes..."
  git commit -m $Message | Out-Host
} else {
  Write-Host "No staged changes to commit."
}

# Push to origin
Write-Host "Pushing to origin/$branch..."
try {
  git push origin $branch | Out-Host
} catch {
  Write-Warning "Initial push failed. Trying to set upstream..."
  git push -u origin $branch | Out-Host
}

Write-Host "Recent commits:" -ForegroundColor Cyan
git --no-pager log --oneline -n 3 | Out-Host

