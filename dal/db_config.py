"""Build the RDS history store at application startup.

Host, port and database name come from environment variables set by
Terraform (``DB_HOST``, ``DB_PORT``, ``DB_NAME``, ``DB_SECRET_ARN``). The
username and password are read from AWS Secrets Manager (the secret named
by ``DB_SECRET_ARN``, an RDS-managed master secret) every time the pool
opens a new connection, so a rotated password is picked up without a
restart. There is deliberately no ``DATABASE_URL`` override, and the
password never sits in an environment variable.

The Secrets Manager region is passed to boto3 explicitly (boto3 itself does
not read ``AWS_REGION``): ``AWS_REGION`` if set, else the region in the secret
ARN. Credentials come from the instance role.
"""

import json
import os
from typing import Any, Mapping, Optional

import boto3
from botocore.config import Config
from sqlalchemy.engine import URL

from dal.rds_store import RDSHistoryStore

REQUIRED_ENV = ('DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_SECRET_ARN')
DRIVER = 'postgresql+psycopg2'
SECRETS_TIMEOUT_SECONDS = 3


class DBConfigError(RuntimeError):
    """The database connection details are missing or invalid."""


def _read_env(env: Mapping[str, str]) -> dict:
    values = {name: (env.get(name) or '').strip() for name in REQUIRED_ENV}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise DBConfigError('missing required environment variables: '
                            + ', '.join(missing))
    return values


def _region(env: Mapping[str, str], arn: str) -> str:
    """``AWS_REGION`` if set, else the region field of the secret ARN."""
    region = (env.get('AWS_REGION') or '').strip()
    if region:
        return region
    # arn:aws:secretsmanager:<region>:<account>:secret:<name>
    parts = arn.split(':')
    if len(parts) > 3 and parts[3]:
        return parts[3]
    raise DBConfigError('no AWS region: set AWS_REGION or use a full secret ARN')


def read_credentials(client: Any, arn: str) -> tuple:
    """Return ``(username, password)`` from the secret ``arn``."""
    try:
        secret = json.loads(client.get_secret_value(SecretId=arn)['SecretString'])
        return secret['username'], secret['password']
    except Exception as exc:
        # Only the exception type: its text could quote the secret.
        raise DBConfigError(f'could not read DB credentials from {arn}: '
                            f'{type(exc).__name__}') from None


def create_history_store(env: Optional[Mapping[str, str]] = None,
                         secrets_client: Optional[Any] = None
                         ) -> RDSHistoryStore:
    """Build an :class:`RDSHistoryStore` whose logins use the live secret.

    Raises:
        DBConfigError: if an environment variable is missing or invalid.
    """
    env_source = os.environ if env is None else env
    values = _read_env(env_source)
    try:
        port = int(values['DB_PORT'])
    except ValueError:
        raise DBConfigError('DB_PORT must be an integer') from None
    arn = values['DB_SECRET_ARN']
    client = secrets_client or boto3.client(
        'secretsmanager', region_name=_region(env_source, arn),
        config=Config(
            connect_timeout=SECRETS_TIMEOUT_SECONDS,
            read_timeout=SECRETS_TIMEOUT_SECONDS,
            retries={'max_attempts': 2}))
    url = URL.create(DRIVER, host=values['DB_HOST'], port=port,
                     database=values['DB_NAME'],
                     query={'sslmode': 'require'})
    return RDSHistoryStore(url, credentials=lambda: read_credentials(client, arn))
