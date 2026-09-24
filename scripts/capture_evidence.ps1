$ErrorActionPreference = "Continue"

if (-not (Test-Path -Path "docs/evidence")) {
    New-Item -ItemType Directory -Path "docs/evidence" | Out-Null
}

Write-Host "Capturing Docker Compose PS..."
docker compose ps | Tee-Object -FilePath "docs/evidence/docker_compose_ps.log"
$dockerStatus = $?

Write-Host "Capturing STS Get-Caller-Identity..."
awslocal sts get-caller-identity | Tee-Object -FilePath "docs/evidence/sts_get_caller_identity.log"
$stsStatus = $?

Write-Host "Capturing CloudTrail Lookup-Events..."
awslocal cloudtrail lookup-events --max-results 5 | Tee-Object -FilePath "docs/evidence/cloudtrail_lookup_events.log"
$ctStatus = $?

Write-Host "======================================"
Write-Host "          EVIDENCE SUMMARY            "
Write-Host "======================================"
Write-Host ("{0,-30} {1}" -f "Check", "Status")
Write-Host ("{0,-30} {1}" -f "------------------------------", "------")

if ($dockerStatus) {
    Write-Host ("{0,-30} {1}" -f "Docker Compose PS", "PASS")
} else {
    Write-Host ("{0,-30} {1}" -f "Docker Compose PS", "FAIL")
}

if ($stsStatus) {
    Write-Host ("{0,-30} {1}" -f "STS Get-Caller-Identity", "PASS")
} else {
    Write-Host ("{0,-30} {1}" -f "STS Get-Caller-Identity", "FAIL")
}

if ($ctStatus) {
    Write-Host ("{0,-30} {1}" -f "CloudTrail Lookup-Events", "PASS")
} else {
    Write-Host ("{0,-30} {1}" -f "CloudTrail Lookup-Events", "FAIL")
}

Write-Host "======================================"
Write-Host "Evidence saved to docs/evidence/"
