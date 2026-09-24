#!/bin/bash
set -euo pipefail

mkdir -p docs/evidence

echo "Capturing Docker Compose PS..."
docker compose ps | tee docs/evidence/docker_compose_ps.log
DOCKER_STATUS=$?

echo "Capturing STS Get-Caller-Identity..."
awslocal sts get-caller-identity | tee docs/evidence/sts_get_caller_identity.log
STS_STATUS=$?

echo "Capturing CloudTrail Lookup-Events..."
awslocal cloudtrail lookup-events --max-results 5 | tee docs/evidence/cloudtrail_lookup_events.log
CT_STATUS=$?

echo "======================================"
echo "          EVIDENCE SUMMARY            "
echo "======================================"
printf "%-30s %s\n" "Check" "Status"
printf "%-30s %s\n" "------------------------------" "------"

if [ $DOCKER_STATUS -eq 0 ]; then
    printf "%-30s %s\n" "Docker Compose PS" "PASS"
else
    printf "%-30s %s\n" "Docker Compose PS" "FAIL"
fi

if [ $STS_STATUS -eq 0 ]; then
    printf "%-30s %s\n" "STS Get-Caller-Identity" "PASS"
else
    printf "%-30s %s\n" "STS Get-Caller-Identity" "FAIL"
fi

if [ $CT_STATUS -eq 0 ]; then
    printf "%-30s %s\n" "CloudTrail Lookup-Events" "PASS"
else
    printf "%-30s %s\n" "CloudTrail Lookup-Events" "FAIL"
fi

echo "======================================"
echo "Evidence saved to docs/evidence/"
