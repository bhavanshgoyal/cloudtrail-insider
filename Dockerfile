FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    git \
    make \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ ./src/
# Create a dummy README.md for pip install to work before mounting
RUN touch README.md && pip install --no-cache-dir awscli awscli-local boto3 && pip install -e ".[dev]"

ENV AWS_ACCESS_KEY_ID=test
ENV AWS_SECRET_ACCESS_KEY=test
ENV AWS_DEFAULT_REGION=us-east-1

CMD ["bash"]
