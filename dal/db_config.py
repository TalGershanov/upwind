"""Build the RDS connection URL at application startup.

Connection details come from two places only:

* Environment variables (set by Terraform on the servers):
  ``DB_HOST``, ``DB_PORT``, ``DB_NAME`` and ``DB_SECRET_ARN``.
* AWS Secrets Manager, read at runtime: the secret named by
  ``DB_SECRET_ARN`` holds ``{"username": ..., "password": ...}``
  (the shape of an RDS-managed master secret).

There is deliberately **no** ``DATABASE_URL`` override: the password must
never live in an environment variable, so the only way to get a URL is
through Secrets Manager.

The result is a :class:`sqlalchemy.engine.URL`, whose ``str``/``repr``
mask the password, so logging it by accident does not leak the secret.
"""

import json
import logging
import os
from typing import Any, Mapping, Optional

from sqlalchemy.engine import URL

from dal.rds_store import RDSHistoryStore

logger = logging.getLogger(__name__)

ENV_HOST = 'DB_HOST'
ENV_PORT = 'DB_PORT'
ENV_NAME = 'DB_NAME'
ENV_SECRET_ARN = 'DB_SECRET_ARN'
REQUIRED_ENV = (ENV_HOST, ENV_PORT, ENV_NAME, ENV_SECRET_ARN)

DRIVER = 'postgresql+psycopg2'
SECRETS_TIMEOUT_SECONDS = 3
SECRETS_MAX_ATTEMPTS = 2


class DBConfigError(RuntimeError):
    """The database connection details are missing or invalid."""


def _read_env(env: Mapping[str, str]) -> dict:
    values = {name: (env.get(name) or '').strip() for name in REQUIRED_ENV}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise DBConfigError('missing required environment variables: '
                            + ', '.join(missing))
    return values


def _parse_port(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError:
        raise DBConfigError(
            f'{ENV_PORT} must be an integer, got {raw!r}') from None
    if not 1 <= port <= 65535:
        raise DBConfigError(f'{ENV_PORT} must be 1-65535, got {port}')
    return port


def _region_from_arn(arn: str) -> str:
    # arn:aws:secretsmanager:<region>:<account>:secret:<name>
    parts = arn.split(':')
    if (len(parts) < 7 or parts[0] != 'arn'
            or parts[2] != 'secretsmanager' or not parts[3]):
        raise DBConfigError(
            f'{ENV_SECRET_ARN} is not a Secrets Manager ARN: {arn!r}')
    return parts[3]


def _default_secrets_client(region: str) -> Any:
    """A boto3 Secrets Manager client with short timeouts.

    Credentials come from the instance role. boto3 is imported lazily so
    the rest of the code (and the tests) don't need it.
    """
    import boto3
    from botocore.config import Config

    return boto3.client(
        'secretsmanager', region_name=region,
        config=Config(connect_timeout=SECRETS_TIMEOUT_SECONDS,
                      read_timeout=SECRETS_TIMEOUT_SECONDS,
                      retries={'max_attempts': SECRETS_MAX_ATTEMPTS}))


def _read_credentials(client: Any, arn: str) -> tuple:
    try:
        response = client.get_secret_value(SecretId=arn)
    except Exception as exc:
        # AWS errors carry codes/ARNs, never the secret value.
        raise DBConfigError(
            f'could not read DB secret {arn}: '
            f'{type(exc).__name__}: {exc}') from exc

    secret_string = response.get('SecretString')
    if not secret_string:
        raise DBConfigError(f'DB secret {arn} has no SecretString')
    try:
        secret = json.loads(secret_string)
    except ValueError:
        # Don't chain: the decode error would quote the secret text.
        raise DBConfigError(f'DB secret {arn} is not valid JSON') from None
    if not isinstance(secret, dict):
        raise DBConfigError(f'DB secret {arn} must be a JSON object')

    missing = [key for key in ('username', 'password')
               if not isinstance(secret.get(key), str) or not secret[key]]
    if missing:
        raise DBConfigError(
            f'DB secret {arn} is missing keys: ' + ', '.join(missing))
    return secret['username'], secret['password']


def build_db_url(env: Optional[Mapping[str, str]] = None,
                 secrets_client: Optional[Any] = None) -> URL:
    """Return the RDS connection URL (``sslmode=require``).

    Args:
        env: Environment variables; ``None`` means ``os.environ``.
        secrets_client: Object with a boto3-style ``get_secret_value``;
            defaults to a real Secrets Manager client for the ARN's region.

    Raises:
        DBConfigError: if any detail is missing, invalid or unreadable.
    """
    values = _read_env(os.environ if env is None else env)
    port = _parse_port(values[ENV_PORT])
    arn = values[ENV_SECRET_ARN]
    region = _region_from_arn(arn)

    if secrets_client is None:
        secrets_client = _default_secrets_client(region)
    username, password = _read_credentials(secrets_client, arn)

    url = URL.create(DRIVER, username=username, password=password,
                     host=values[ENV_HOST], port=port,
                     database=values[ENV_NAME],
                     query={'sslmode': 'require'})
    logger.info('DB connection configured for %s:%d/%s (secret %s)',
                values[ENV_HOST], port, values[ENV_NAME], arn)
    return url


def create_history_store(env: Optional[Mapping[str, str]] = None,
                         secrets_client: Optional[Any] = None
                         ) -> RDSHistoryStore:
    """Build an :class:`RDSHistoryStore` that survives secret rotation.

    On a DB auth failure the store calls :func:`build_db_url` again,
    re-reading the secret, and retries once. One Secrets Manager client
    is built here and reused for every refresh.
    """
    env = os.environ if env is None else env
    if secrets_client is None:
        arn = _read_env(env)[ENV_SECRET_ARN]
        secrets_client = _default_secrets_client(_region_from_arn(arn))
    return RDSHistoryStore(
        build_db_url(env, secrets_client),
        refresh_url=lambda: build_db_url(env, secrets_client))
