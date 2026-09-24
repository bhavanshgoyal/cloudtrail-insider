$ErrorActionPreference = "Stop"

Write-Host "Bootstrapping LocalStack environment..."

Write-Host "Waiting for LocalStack..."
while ($true) {
    try {
        $health = Invoke-RestMethod -Uri "http://localhost:4566/_localstack/health" -ErrorAction SilentlyContinue
        if ($health.services.s3 -eq "available" -or $health.services.s3 -eq "running") {
            break
        }
    } catch {}
    Start-Sleep -Seconds 2
}

$env:AWS_ACCESS_KEY_ID="test"
$env:AWS_SECRET_ACCESS_KEY="test"
$env:AWS_DEFAULT_REGION="us-east-1"

Write-Host "Creating S3 buckets..."
aws --endpoint-url http://localhost:4566 s3 mb s3://cloudtrail-logs-bucket
aws --endpoint-url http://localhost:4566 s3 mb s3://finance-archive
aws --endpoint-url http://localhost:4566 s3 mb s3://public-assets-bucket

Write-Host "Tagging S3 buckets..."
aws --endpoint-url http://localhost:4566 s3api put-bucket-tagging --bucket finance-archive --tagging 'TagSet=[{Key=sensitivity,Value=high}]'

Write-Host "Creating CloudTrail trail..."
aws --endpoint-url http://localhost:4566 cloudtrail create-trail --name local-audit-trail --s3-bucket-name cloudtrail-logs-bucket --include-global-service-events --is-multi-region-trail
aws --endpoint-url http://localhost:4566 cloudtrail start-logging --name local-audit-trail

Write-Host "Creating IAM Roles..."
$policy = '{"Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}'
aws --endpoint-url http://localhost:4566 iam create-role --role-name analyst --assume-role-policy-document $policy
aws --endpoint-url http://localhost:4566 iam create-role --role-name admin --assume-role-policy-document $policy
aws --endpoint-url http://localhost:4566 iam create-role --role-name backup-service --assume-role-policy-document $policy

Write-Host "Bootstrap complete!"
