from django.utils.timezone import now
from jose import jwt
from okta_oauth2.conf import Config


def build_token(
    aud=None,
    auth_time=None,
    exp=None,
    iat=None,
    iss=None,
    sub=None,
    nonce="defaultnonce",
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
    }

    headers = {"kid": "1A234567890"}

    return jwt.encode(claims, "secret", headers=headers, algorithm="HS256")
