"""Optional AWS Secrets Manager injection before application settings are evaluated."""
import json
import os

_ALLOWED = frozenset({"OAUTH_DB_URL", "OAUTH_REDIS_URL", "OAUTH_METRICS_KEY", "OAUTH_ADMIN_API_KEY"})


def load_aws_secrets() -> None:
    arn = os.getenv("OAUTH_AWS_SECRET_ARN", "")
    if not arn:
        return
    import boto3
    response = boto3.client("secretsmanager").get_secret_value(SecretId=arn)
    payload = response.get("SecretString")
    if not payload or len(payload) > 16384:
        raise ValueError("AWS secret must contain a reasonably sized JSON object")
    values = json.loads(payload)
    if not isinstance(values, dict) or not values or set(values) - _ALLOWED:
        raise ValueError("AWS secret contains unknown keys")
    for key, value in values.items():
        if not isinstance(value, str) or not value:
            raise ValueError(f"Secret {key} must be a nonempty string")
        # The managed secret is authoritative if configured, not a fallback.
        os.environ[key] = value
