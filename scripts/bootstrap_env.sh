#!/bin/bash
set -euo pipefail

echo "Bootstrapping LocalStack environment..."

# Wait for LocalStack to be ready
echo "Waiting for LocalStack..."
until curl -s http://localhost:4566/_localstack/health | grep -q '"cloudtrail": "available"'; do
    sleep 2
done

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1

echo "Creating S3 buckets..."
awslocal s3 mb s3://cloudtrail-logs-bucket
awslocal s3 mb s3://finance-archive
awslocal s3 mb s3://public-assets-bucket

echo "Tagging S3 buckets..."
awslocal s3api put-bucket-tagging \
    --bucket finance-archive \
    --tagging 'TagSet=[{Key=sensitivity,Value=high}]'

echo "Creating CloudTrail trail..."
awslocal cloudtrail create-trail \
    --name local-audit-trail \
    --s3-bucket-name cloudtrail-logs-bucket \
    --include-global-service-events \
    --is-multi-region-trail

awslocal cloudtrail start-logging --name local-audit-trail

echo "Creating IAM Roles..."
awslocal iam create-role --role-name analyst --assume-role-policy-document '{"Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}'
awslocal iam create-role --role-name admin --assume-role-policy-document '{"Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}'
awslocal iam create-role --role-name backup-service --assume-role-policy-document '{"Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}'

echo "Bootstrap complete!"
