"""boto3 client factory. `local=True` points at LocalStack with dummy credentials."""
from __future__ import annotations

import os
from typing import Any

import boto3

LOCALSTACK_ENDPOINT = "http://localhost:4566"


def make_client(service: str, local: bool = False, endpoint: str | None = None,
                creds: dict[str, str] | None = None, region: str | None = None) -> Any:
    region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    kwargs: dict[str, Any] = {"region_name": region}
    if local or endpoint:
        kwargs["endpoint_url"] = endpoint or os.environ.get("PIPELINEGUARD_ENDPOINT", LOCALSTACK_ENDPOINT)
        kwargs["aws_access_key_id"] = "test"
        kwargs["aws_secret_access_key"] = "test"
    if creds:
        kwargs["aws_access_key_id"] = creds["AccessKeyId"]
        kwargs["aws_secret_access_key"] = creds["SecretAccessKey"]
        kwargs["aws_session_token"] = creds.get("SessionToken")
    return boto3.client(service, **kwargs)
