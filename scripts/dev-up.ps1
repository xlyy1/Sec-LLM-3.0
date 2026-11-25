# Start the local stack and wait until every healthcheck passes.
$ErrorActionPreference = "Stop"

if (-not (Test-Path (Join-Path $PSScriptRoot "..\docker-compose.yml"))) {
    throw "Run this from the repository root (scripts/dev-up.ps1)."
}

Push-Location (Join-Path $PSScriptRoot "..")
try {
    docker compose up -d --build --wait --wait-timeout 600
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed (exit $LASTEXITCODE)" }

    Write-Host ""
    Write-Host "Backend:  http://localhost:8000/docs"
    Write-Host "Frontend: http://localhost:3000"
    Write-Host ""
    docker compose ps
}
finally {
    Pop-Location
}
