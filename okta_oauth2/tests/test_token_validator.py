from unittest.mock import MagicMock, Mock, patch

import pytest
from django.contrib.auth.models import Group
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import caches
from django.utils.timezone import now
from okta_oauth2.conf import Config
from okta_oauth2.exceptions import (
    InvalidClientID,
    InvalidTokenSignature,
    IssuerDoesNotMatch,
    NonceDoesNotMatch,
    TokenExpired,
    TokenRequestFailed,
    TokenTooFarAway,
)
from okta_oauth2.tests.utils import (
    build_access_token,
    build_id_token,
    update_okta_settings,
)
from okta_oauth2.tokens import DiscoveryDocument, TokenValidator

SUPERUSER_GROUP = "Superusers"
STAFF_GROUP = "Staff"

KEY_1 = {
    "alg": "RS256",
    "e": "AQAB",
    "n": """iKqiD4cr7FZKm6f05K4r-GQOvjRqjOeFmOho9V7SAXYwCyJluaGBLVvDWO1XlduPLOrsG_Wgs67SOG5qeLPR8T1zDK4bfJAo1Tvbw
            YeTwVSfd_0mzRq8WaVc_2JtEK7J-4Z0MdVm_dJmcMHVfDziCRohSZthN__WM2NwGnbewWnla0wpEsU3QMZ05_OxvbBdQZaDUsNSx4
            6is29eCdYwhkAfFd_cFRq3DixLEYUsRwmOqwABwwDjBTNvgZOomrtD8BRFWSTlwsbrNZtJMYU33wuLO9ynFkZnY6qRKVHr3YToIrq
            NBXw0RWCheTouQ-snfAB6wcE2WDN3N5z760ejqQ""",
    "kid": "U5R8cHbGw445Qbq8zVO1PcCpXL8yG6IcovVa3laCoxM",
    "kty": "RSA",
    "use": "sig",
}

KEY_2 = {
    "alg": "RS256",
    "e": "AQAB",
    "n": """l1hZ_g2sgBE3oHvu34T-5XP18FYJWgtul_nRNg-5xra5ySkaXEOJUDRERUG0HrR42uqf9jYrUTwg9fp-SqqNIdHRaN8EwRSDRsKAwK
            3HIJ2NJfgmrrO2ABkeyUq6rzHxAumiKv1iLFpSawSIiTEBJERtUCDcjbbqyHVFuivIFgH8L37-XDIDb0XG-R8DOoOHLJPTpsgH-rJe
            M5w96VIRZInsGC5OGWkFdtgk6OkbvVd7_TXcxLCpWeg1vlbmX-0TmG5yjSj7ek05txcpxIqYu-7FIGT0KKvXge_BOSEUlJpBhLKU28
            OtsOnmc3NLIGXB-GeDiUZiBYQdPR-myB4ZoQ""",
    "kid": "Y3vBOdYT-l-I0j-gRQ26XjutSX00TeWiSguuDhW3ngo",
    "kty": "RSA",
    "use": "sig",
}


def mock_request_jwks(self):
    return {"keys": [KEY_1, KEY_2]}


def get_token_result(self, code):
    return {
        "access_token": build_access_token(),
        "id_token": build_id_token(),
        "refresh_token": "refresh",
    }


def get_superuser_token_result(self, code):
    return {
        "access_token": build_access_token(),
        "id_token": build_id_token(groups=[SUPERUSER_GROUP]),
        "refresh_token": "refresh",
    }


def get_staff_token_result(self, code):
    return {
        "access_token": build_access_token(),
        "id_token": build_id_token(groups=[STAFF_GROUP]),
        "refresh_token": "refresh",
    }


def get_normal_user_with_groups_token(self, code):
    return {
        "access_token": build_access_token(),
        "id_token": build_id_token(groups=["one", "two"]),
        "refresh_token": "refresh",
    }


def add_session(req):
    mw = SessionMiddleware("response")
    mw.process_request(req)
    req.session.save()


@patch("okta_oauth2.tokens.requests.get")
def test_discovery_document_sets_json(mock_get):
    mock_get.return_value = Mock(ok=True)
    mock_get.return_value.json.return_value = {"key": "value"}

    d = DiscoveryDocument("http://notreal.example.com")
    assert d.getJson() == {"key": "value"}


def test_token_validator_gets_token_from_auth_code(rf, django_user_model):
    """
    We should get our tokens back with a user.
    """
    c = Config()
    req = rf.get("/")
    add_session(req)

    with patch(
        "okta_oauth2.tokens.TokenValidator.call_token_endpoint", get_token_result
    ), patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        tv = TokenValidator(c, "defaultnonce", req)
        user, tokens = tv.tokens_from_auth_code("authcode")
        assert "access_token" in tokens
        assert "id_token" in tokens
        assert isinstance(user, django_user_model)


def test_token_validator_gets_token_from_refresh_token(rf, django_user_model):
    """
    We should get our tokens back with a user.
    """
    c = Config()
    req = rf.get("/")
    add_session(req)

    with patch(
        "okta_oauth2.tokens.TokenValidator.call_token_endpoint", get_token_result
    ), patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        tv = TokenValidator(c, "defaultnonce", req)
        user, tokens = tv.tokens_from_refresh_token("refresh")
        assert "access_token" in tokens
        assert "id_token" in tokens
        assert isinstance(user, django_user_model)


def test_handle_token_result_handles_missing_tokens(rf):
    """
    If we didn't get any tokens back, don't return a user
    and return the empty token dict so we can check why later.
    """
    c = Config()
    req = rf.get("/")

    tv = TokenValidator(c, "defaultnonce", req)
    result = tv.handle_token_result({})
    assert result == (None, {})


@pytest.mark.django_db
def test_created_user_if_part_of_superuser_group(rf, settings, django_user_model):
    """
    If the user is part of the superuser group defined
    in settings make sure that the created user is a superuser.
    """
    settings.OKTA_AUTH = update_okta_settings(
        settings.OKTA_AUTH, "SUPERUSER_GROUP", SUPERUSER_GROUP
    )

    c = Config()
    req = rf.get("/")
    add_session(req)

    with patch(
        "okta_oauth2.tokens.TokenValidator.call_token_endpoint",
        get_superuser_token_result,
    ), patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        tv = TokenValidator(c, "defaultnonce", req)
        user, tokens = tv.tokens_from_refresh_token("refresh")
        assert isinstance(user, django_user_model)
        assert user.is_superuser


@patch("okta_oauth2.tokens.requests.post")
def test_call_token_endpoint_returns_tokens(mock_post, rf):
    """
    when we call the token endpoint with valid data we expect
    to receive a bunch of tokens. See assertions to understand which.
    """
    mock_post.return_value = Mock(ok=True)
    mock_post.return_value.json.return_value = {
        "access_token": build_access_token(),
        "id_token": build_id_token(),
        "refresh_token": "refresh",
    }
    endpoint_data = {"grant_type": "authorization_code", "code": "imacode"}

    c = Config()
    MockDiscoveryDocument = MagicMock()

    with patch("okta_oauth2.tokens.DiscoveryDocument", MockDiscoveryDocument):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        tokens = tv.call_token_endpoint(endpoint_data)
        assert "access_token" in tokens
        assert "id_token" in tokens
        assert "refresh_token" in tokens


@patch("okta_oauth2.tokens.requests.post")
def test_call_token_endpoint_handles_error(mock_post, rf):
    """
    When we get an error back from the API we should be
    raising an TokenRequestFailed error.
    """
    mock_post.return_value = Mock(ok=True)
    mock_post.return_value.json.return_value = {
        "error": "failure",
        "error_description": "something went wrong",
    }
    endpoint_data = {"grant_type": "authorization_code", "code": "imacode"}

    c = Config()
    MockDiscoveryDocument = MagicMock()

    with patch(
        "okta_oauth2.tokens.DiscoveryDocument", MockDiscoveryDocument
    ), pytest.raises(TokenRequestFailed):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        tv.call_token_endpoint(endpoint_data)


def test_jwks_returns_cached_key(rf):
    """
    _jwks method should return a cached key if
    there's one in the cache with a matching ID.
    """
    c = Config()
    tv = TokenValidator(c, "defaultnonce", rf.get("/"))
    cache = caches[c.cache_alias]
    cache.set(tv.cache_key, [KEY_1], c.cache_timeout)
    key = tv._jwks(KEY_1["kid"])
    assert key == KEY_1


def test_jwks_sets_cache_and_returns(rf):
    """
    _jwks method should request keys from okta,
    and if they match the key we're looking for,
    cache and return it.
    """
    c = Config()

    with patch(
        "okta_oauth2.tokens.TokenValidator.request_jwks", mock_request_jwks
    ), patch("okta_oauth2.tokens.DiscoveryDocument", MagicMock()):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        key = tv._jwks(KEY_2["kid"])
        cache = caches[c.cache_alias]
        cached_keys = cache.get(tv.cache_key)
        assert key == KEY_2
        assert KEY_2 in cached_keys


@patch("okta_oauth2.tokens.requests.get")
def test_request_jwks(mock_get, rf):
    """ Test jwks method returns json """
    mock_get.return_value = Mock(ok=True)
    mock_get.return_value.json.return_value = mock_request_jwks(None)

    c = Config()

    with patch("okta_oauth2.tokens.TokenValidator._discovery_document", MagicMock()):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        result = tv.request_jwks()
        assert result == mock_request_jwks(None)


def test_jwks_returns_if_none_found(rf):
    """ The _jwks method should return None if no key is found. """
    c = Config()

    with patch(
        "okta_oauth2.tokens.TokenValidator.request_jwks", mock_request_jwks
    ), patch("okta_oauth2.tokens.DiscoveryDocument", MagicMock()):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        assert tv._jwks("notakey") is None


def test_validate_token_successfully_validates(rf):
    """ A valid token should return the decoded token. """
    token = build_id_token()
    c = Config()
    with patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        decoded_token = tv.validate_token(token)
        assert decoded_token["jti"] == "randomid"


def test_wrong_key_raises_invalid_token(rf):
    """
    If we get the wrong key then we should be raising an InvalidTokenSignature.
    """
    token = build_id_token()
    c = Config()
    with patch(
        "okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="wrongkey")
    ), pytest.raises(InvalidTokenSignature):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        tv.validate_token(token)


def test_no_key_raises_invalid_token(rf):
    """
    If we dont' have a key at all we should be raising an InvalidTokenSignature.
    """
    token = build_id_token()
    c = Config()
    with patch(
        "okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value=None)
    ), pytest.raises(InvalidTokenSignature):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        tv.validate_token(token)


def test_invalid_issuer_in_decoded_token(rf):
    """
    If our issuers don't match we should raise an IssuerDoesNotMatch.
    """
    token = build_id_token(iss="invalid-issuer")
    c = Config()

    with patch(
        "okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")
    ), pytest.raises(IssuerDoesNotMatch):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        tv.validate_token(token)


def test_invalid_audience_in_decoded_token(rf):
    """
    If our audience doesn't match our client id we should raise an InvalidClientID
    """
    token = build_id_token(aud="invalid-aud")
    c = Config()

    with patch(
        "okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")
    ), pytest.raises(InvalidClientID):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        tv.validate_token(token)


def test_expired_token_raises_error(rf):
    """
    If our token is expired then we should raise an TokenExpired.
    """
    token = build_id_token(exp=now().timestamp() - 3600)
    c = Config()

    with patch(
        "okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")
    ), pytest.raises(TokenExpired):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        tv.validate_token(token)


def test_issue_time_is_too_far_in_the_past_raises_error(rf):
    """
    If our token was issued more than about 24 hours ago
    we want to raise a TokenTooFarAway.
    """
    token = build_id_token(iat=now().timestamp() - 200000)
    c = Config()

    with patch(
        "okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")
    ), pytest.raises(TokenTooFarAway):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        tv.validate_token(token)


def test_unmatching_nonce_raises_error(rf):
    """
    If our token has the wrong nonce then raise a NonceDoesNotMatch
    """
    token = build_id_token(nonce="wrong-nonce")
    c = Config()

    with patch(
        "okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")
    ), pytest.raises(NonceDoesNotMatch):
        tv = TokenValidator(c, "defaultnonce", rf.get("/"))
        tv.validate_token(token)


@pytest.mark.django_db
def test_groups_are_created_and_user_added(rf, settings, django_user_model):
    """
    If MANAGE_GROUPS is true the groups should be created and the user
    should be added to them.
    """
    settings.OKTA_AUTH = update_okta_settings(settings.OKTA_AUTH, "MANAGE_GROUPS", True)

    c = Config()
    req = rf.get("/")
    add_session(req)

    with patch(
        "okta_oauth2.tokens.TokenValidator.call_token_endpoint",
        get_normal_user_with_groups_token,
    ), patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        tv = TokenValidator(c, "defaultnonce", req)
        user, tokens = tv.tokens_from_refresh_token("refresh")

        groups = Group.objects.all()
        assert [("one",), ("two",)] == list(groups.values_list("name"))
        assert list(user.groups.all()) == list(Group.objects.all())


@pytest.mark.django_db
def test_user_is_removed_from_groups(rf, settings, django_user_model):
    """
    When MANAGE_GROUPS is true a user should be removed from a
    group if it's not included in the token response.
    """
    settings.OKTA_AUTH = update_okta_settings(settings.OKTA_AUTH, "MANAGE_GROUPS", True)

    user = django_user_model._default_manager.create_user(
        username="fakemail@notreal.com", email="fakemail@notreal.com"
    )
    group = Group.objects.create(name="test-group")

    user.groups.add(group)

    c = Config()
    req = rf.get("/")
    add_session(req)

    with patch(
        "okta_oauth2.tokens.TokenValidator.call_token_endpoint",
        get_normal_user_with_groups_token,
    ), patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        tv = TokenValidator(c, "defaultnonce", req)
        user, tokens = tv.tokens_from_refresh_token("refresh")

        groups = user.groups.all()
        assert [("one",), ("two",)] == list(groups.values_list("name"))


@pytest.mark.django_db
def test_existing_user_is_escalated_to_superuser_group(rf, settings, django_user_model):
    """
    If an existing user is added to a superuser group they should
    be escalated to a superuser.
    """
    settings.OKTA_AUTH = update_okta_settings(
        settings.OKTA_AUTH, "SUPERUSER_GROUP", SUPERUSER_GROUP
    )

    user = django_user_model._default_manager.create_user(
        username="fakemail@notreal.com", email="fakemail@notreal.com"
    )

    c = Config()
    req = rf.get("/")
    add_session(req)

    with patch(
        "okta_oauth2.tokens.TokenValidator.call_token_endpoint",
        get_superuser_token_result,
    ), patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        tv = TokenValidator(c, "defaultnonce", req)
        user, tokens = tv.tokens_from_refresh_token("refresh")
        assert isinstance(user, django_user_model)
        assert user.is_superuser


@pytest.mark.django_db
def test_existing_superuser_is_deescalated_from_superuser_group(
    rf, settings, django_user_model
):
    """
    If an existing user is removed from a superuser group they should
    be deescalated from a superuser.
    """
    settings.OKTA_AUTH = update_okta_settings(
        settings.OKTA_AUTH, "SUPERUSER_GROUP", SUPERUSER_GROUP
    )

    user = django_user_model._default_manager.create_user(
        username="fakemail@notreal.com",
        email="fakemail@notreal.com",
        is_staff=True,
        is_superuser=True,
    )

    c = Config()
    req = rf.get("/")
    add_session(req)

    with patch(
        "okta_oauth2.tokens.TokenValidator.call_token_endpoint",
        get_normal_user_with_groups_token,
    ), patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        tv = TokenValidator(c, "defaultnonce", req)
        user, tokens = tv.tokens_from_refresh_token("refresh")
        assert isinstance(user, django_user_model)
        assert user.is_superuser is False


@pytest.mark.django_db
def test_existing_user_is_escalated_to_staff_group(rf, settings, django_user_model):
    """
    If an existing user is added to a staff group they should
    be escalated to a superuser.
    """
    settings.OKTA_AUTH = update_okta_settings(
        settings.OKTA_AUTH, "STAFF_GROUP", STAFF_GROUP
    )

    user = django_user_model._default_manager.create_user(
        username="fakemail@notreal.com", email="fakemail@notreal.com"
    )

    c = Config()
    req = rf.get("/")
    add_session(req)

    with patch(
        "okta_oauth2.tokens.TokenValidator.call_token_endpoint",
        get_staff_token_result,
    ), patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        tv = TokenValidator(c, "defaultnonce", req)
        user, tokens = tv.tokens_from_refresh_token("refresh")
        assert isinstance(user, django_user_model)
        assert user.is_staff


@pytest.mark.django_db
def test_existing_superuser_is_deescalated_from_staff_group(
    rf, settings, django_user_model
):
    """
    If an existing user is removed from a staff group they should
    have the staff flag removed.
    """
    settings.OKTA_AUTH = update_okta_settings(
        settings.OKTA_AUTH, "STAFF_GROUP", STAFF_GROUP
    )

    user = django_user_model._default_manager.create_user(
        username="fakemail@notreal.com",
        email="fakemail@notreal.com",
        is_staff=True,
    )

    c = Config()
    req = rf.get("/")
    add_session(req)

    with patch(
        "okta_oauth2.tokens.TokenValidator.call_token_endpoint",
        get_normal_user_with_groups_token,
    ), patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        tv = TokenValidator(c, "defaultnonce", req)
        user, tokens = tv.tokens_from_refresh_token("refresh")
        assert isinstance(user, django_user_model)
        assert user.is_staff is False
