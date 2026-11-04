"""Tests for dal.db_config: no AWS or network, uses a fake secrets client."""

import json
import logging

import pytest

from dal import db_config
from dal.db_config import DBConfigError, build_db_url

ARN = ('arn:aws:secretsmanager:eu-west-1:123456789012:'
       'secret:rds!db-abc123-XyZ')
PASSWORD = 'S3cr3t-Pa55word'


class FakeSecretsClient:
    """Stands in for boto3's Secrets Manager client."""

    def __init__(self, secret=None, secret_string=None, error=None):
        if secret_string is None and secret is not None:
            secret_string = json.dumps(secret)
        self.secret_string = secret_string
        self.error = error
        self.calls = []

    def get_secret_value(self, SecretId):
        self.calls.append(SecretId)
        if self.error is not None:
            raise self.error
        response = {'ARN': SecretId}
        if self.secret_string is not None:
            response['SecretString'] = self.secret_string
        return response


def make_env(**overrides):
    env = {'DB_HOST': 'mydb.abc.eu-west-1.rds.amazonaws.com',
           'DB_PORT': '5432',
           'DB_NAME': 'phishing',
           'DB_SECRET_ARN': ARN}
    env.update(overrides)
    return {k: v for k, v in env.items() if v is not None}


def fake_client(username='app', password=PASSWORD):
    return FakeSecretsClient({'username': username, 'password': password})


class TestHappyPath:
    def test_builds_url_from_env_and_secret(self):
        client = fake_client()
        url = build_db_url(make_env(), client)
        assert url.drivername == 'postgresql+psycopg2'
        assert url.host == 'mydb.abc.eu-west-1.rds.amazonaws.com'
        assert url.port == 5432
        assert url.database == 'phishing'
        assert url.username == 'app'
        assert url.password == PASSWORD
        assert url.query['sslmode'] == 'require'
        assert client.calls == [ARN]

    def test_strips_whitespace_from_env(self):
        url = build_db_url(make_env(DB_HOST='  h.example  ',
                                    DB_PORT=' 6543 '), fake_client())
        assert url.host == 'h.example'
        assert url.port == 6543

    def test_special_characters_in_password_round_trip(self):
        password = 'p@ss:/w#rd?&%'
        url = build_db_url(make_env(), fake_client(password=password))
        assert url.password == password
        rendered = url.render_as_string(hide_password=False)
        assert password not in rendered  # escaped inside the URL string

    def test_str_and_repr_hide_password(self):
        url = build_db_url(make_env(), fake_client())
        assert PASSWORD not in str(url)
        assert PASSWORD not in repr(url)

    def test_password_not_logged(self, caplog):
        with caplog.at_level(logging.DEBUG):
            build_db_url(make_env(), fake_client())
        assert caplog.records
        assert PASSWORD not in caplog.text

    def test_default_client_uses_region_from_arn(self, monkeypatch):
        regions = []
        client = fake_client()

        def factory(region):
            regions.append(region)
            return client

        monkeypatch.setattr(db_config, '_default_secrets_client', factory)
        build_db_url(make_env())
        assert regions == ['eu-west-1']
        assert client.calls == [ARN]


class TestNoDatabaseUrlOverride:
    def test_database_url_is_ignored(self):
        env = make_env(DATABASE_URL='postgresql://evil:pw@other/db')
        url = build_db_url(env, fake_client())
        assert url.host == 'mydb.abc.eu-west-1.rds.amazonaws.com'
        assert url.username == 'app'

    def test_database_url_does_not_replace_missing_vars(self):
        env = {'DATABASE_URL': 'postgresql://u:p@h/db'}
        client = fake_client()
        with pytest.raises(DBConfigError, match='DB_HOST'):
            build_db_url(env, client)
        assert client.calls == []


class TestEnvValidation:
    @pytest.mark.parametrize('name', db_config.REQUIRED_ENV)
    def test_single_missing_var(self, name):
        client = fake_client()
        with pytest.raises(DBConfigError, match=name):
            build_db_url(make_env(**{name: None}), client)
        assert client.calls == []

    def test_all_missing_vars_reported_together(self):
        with pytest.raises(DBConfigError) as info:
            build_db_url(make_env(DB_HOST=None, DB_SECRET_ARN=None),
                         fake_client())
        message = str(info.value)
        assert 'DB_HOST' in message and 'DB_SECRET_ARN' in message
        assert 'DB_PORT' not in message

    def test_blank_value_counts_as_missing(self):
        with pytest.raises(DBConfigError, match='DB_NAME'):
            build_db_url(make_env(DB_NAME='   '), fake_client())

    @pytest.mark.parametrize('port', ['abc', '54.32'])
    def test_non_integer_port(self, port):
        with pytest.raises(DBConfigError, match='DB_PORT must be an integer'):
            build_db_url(make_env(DB_PORT=port), fake_client())

    @pytest.mark.parametrize('port', ['0', '65536', '-1'])
    def test_out_of_range_port(self, port):
        with pytest.raises(DBConfigError, match='DB_PORT must be 1-65535'):
            build_db_url(make_env(DB_PORT=port), fake_client())

    @pytest.mark.parametrize('arn', [
        'not-an-arn',
        'arn:aws:s3:eu-west-1:123456789012:secret:x',
        'arn:aws:secretsmanager::123456789012:secret:x',
    ])
    def test_malformed_arn(self, arn):
        client = fake_client()
        with pytest.raises(DBConfigError, match='DB_SECRET_ARN'):
            build_db_url(make_env(DB_SECRET_ARN=arn), client)
        assert client.calls == []


class TestSecretValidation:
    def test_client_error_is_wrapped(self):
        client = FakeSecretsClient(error=TimeoutError('connect timed out'))
        with pytest.raises(DBConfigError, match='could not read DB secret'):
            build_db_url(make_env(), client)

    def test_missing_secret_string(self):
        with pytest.raises(DBConfigError, match='no SecretString'):
            build_db_url(make_env(), FakeSecretsClient())

    def test_invalid_json_does_not_leak_secret(self):
        bad = 'password=' + PASSWORD
        with pytest.raises(DBConfigError, match='not valid JSON') as info:
            build_db_url(make_env(), FakeSecretsClient(secret_string=bad))
        assert PASSWORD not in str(info.value)
        assert info.value.__cause__ is None

    def test_non_object_json(self):
        with pytest.raises(DBConfigError, match='JSON object'):
            build_db_url(make_env(), FakeSecretsClient(secret=[PASSWORD]))

    @pytest.mark.parametrize('secret, missing', [
        ({'username': 'app'}, 'password'),
        ({'password': PASSWORD}, 'username'),
        ({'username': '', 'password': PASSWORD}, 'username'),
    ])
    def test_missing_keys_named_without_values(self, secret, missing):
        with pytest.raises(DBConfigError, match=missing) as info:
            build_db_url(make_env(), FakeSecretsClient(secret))
        assert PASSWORD not in str(info.value)


class TestDefaultSecretsClient:
    def test_builds_regional_client_with_short_timeouts(self, monkeypatch):
        boto3 = pytest.importorskip('boto3')
        created = {}

        def fake_client(service, region_name, config):
            created.update(service=service, region=region_name,
                           config=config)
            return object()

        monkeypatch.setattr(boto3, 'client', fake_client)
        db_config._default_secrets_client('eu-west-1')
        assert created['service'] == 'secretsmanager'
        assert created['region'] == 'eu-west-1'
        assert created['config'].connect_timeout == \
            db_config.SECRETS_TIMEOUT_SECONDS
        assert created['config'].read_timeout == \
            db_config.SECRETS_TIMEOUT_SECONDS
        assert created['config'].retries['max_attempts'] == \
            db_config.SECRETS_MAX_ATTEMPTS
