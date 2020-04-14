from django.utils.timezone import now
from jose import jwt
from okta_oauth2.conf import Config


def update_okta_settings(okta_settings, k, v):
    """
    Pytest-django does a shallow compare to determine which parts
    of its settings fixture to roll back, so if we don't replace
    the OKTA_AUTH dict entirely settings don't roll back between tests.
    """
    new_settings = okta_settings.copy()
    new_settings.update({k: v})
    return new_settings


def build_id_token(
    aud=None,
    auth_time=None,
    exp=None,
    iat=None,
    iss=None,
    sub=None,
    nonce="defaultnonce",
    groups=[],
):
    config = Config()

    current_timestamp = now().timestamp()
    iat_offset = 2

    claims = {
        "amr": ["pwd"],
        "at_hash": "notarealhash",
        "aud": aud if aud else config.client_id,
        "auth_time": auth_time if auth_time else current_timestamp,
        "email": "fakemail@notreal.com",
        "exp": exp if exp else current_timestamp + iat_offset + 3600,
        "iat": iat if iat else current_timestamp + iat_offset,
        "idp": aud if aud else config.client_id,
        "iss": iss if iss else config.issuer,
        "jti": "randomid",
        "name": "A User",
        "nonce": nonce,
        "preferred_username": "auser",
        "sub": sub if sub else config.client_id,
        "ver": 1,
        "groups": groups,
    }

    headers = {"kid": "1A234567890"}

    return jwt.encode(claims, "secret", headers=headers, algorithm="HS256")


def build_access_token(
    aud=None, auth_time=None, exp=None, iat=None, iss=None, sub=None, uid=None
):
    config = Config()

    current_timestamp = now().timestamp()
    iat_offset = 2

    headers = {"alg": "HS256", "kid": "abcdefg"}

    claims = {
        "ver": 1,
        "jti": "randomid",
        "iss": iss if iss else config.issuer,
        "aud": aud if aud else config.client_id,
        "sub": sub if sub else config.client_id,
        "iat": iat if iat else current_timestamp + iat_offset,
        "exp": exp if exp else current_timestamp + iat_offset + 3600,
        "uid": uid if uid else config.client_id,
        "scp": ["openid", "email", "offline_access", "groups"],
    }

    return jwt.encode(claims, "secret", headers=headers, algorithm="HS256")
