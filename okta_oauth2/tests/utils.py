from django.utils.timezone import now
from jose import jwt

from okta_oauth2.conf import Config

TEST_PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC3UnFAPMb32q3IcBTbG46qLamnh0CbqPwEQKn9wrzBFhJ3nhtB
FQStNI8TXUPLN87i7hZt8tX4iWkUYJskwz98qZj8vc7LhT6/MBulyLyMP2VYva2D
ufezz5qX6n/xBo6bgv1XsTyS4EdBN9QL2oc23bu7MUoDsor0tNGuy5xKjQIDAQAB
AoGBAJ1qAmtJhQSBV2Zcr9vxTtDcguii4ByJv1WbfRy0okYewN7L+dUpyik8j3ru
Q+91TYZZMRNaSNewjnV7+txXd+QM5mLorfmYEIuvxVf6edXgzRuNfol1UO0gjWl3
wpoNUQXHqSp7f2pluLw/wTFAgFOWTMmE4tdFe4KCImmkljW1AkEA2Saus/usqA4r
QfroAdLn2dKR6kO2LXdORpaNZ1NgXw4+nqDMYNBPilOUh5L+fq8VzNF0o50PfO83
u74oknT4twJBANgea6Xp37V2QLnU2G98DGd9E24EqvQkRopDq0kYdXzNpsVLx7fu
76QXSPO4OqxzlIq3HguWlK+oKEBOZ3iuqtsCQQDNaj07Puk99GFRQfM0vnjaYcns
LG9qJQDj30kWJBX29XehAQU00/laJeRMN24NErzxinXmzA05puU28RRaLtKTAkAi
5H5y0hipPodiuWecUEXca4g4ig5jznuJFTXRXl6RoM5dKkf7fVs5ffzsRIFMmHiS
ENCMBGrLFXYyM7Zm+KRjAkAJFILd+qtdADilYbyf4KPU766TT1dtljAoTBzxZ0T9
2VblbIa1tmvs35apo6fxFf4dXOZNiz85OMFvxglvmIus
-----END RSA PRIVATE KEY-----
"""

TEST_PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3UnFAPMb32q3IcBTbG46qLamn
h0CbqPwEQKn9wrzBFhJ3nhtBFQStNI8TXUPLN87i7hZt8tX4iWkUYJskwz98qZj8
vc7LhT6/MBulyLyMP2VYva2Dufezz5qX6n/xBo6bgv1XsTyS4EdBN9QL2oc23bu7
MUoDsor0tNGuy5xKjQIDAQAB
-----END PUBLIC KEY-----
"""


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

    return jwt.encode(claims, TEST_PRIVATE_KEY, headers=headers, algorithm="RS256")


def build_access_token(
    aud=None, auth_time=None, exp=None, iat=None, iss=None, sub=None, uid=None
):
    config = Config()

    current_timestamp = now().timestamp()
    iat_offset = 2

    headers = {"alg": "RS256", "kid": "abcdefg"}

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

    return jwt.encode(claims, TEST_PRIVATE_KEY, headers=headers, algorithm="RS256")
