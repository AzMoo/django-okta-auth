from unittest.mock import Mock, patch

from django.http import HttpResponse
from django.urls import reverse
from okta_oauth2.exceptions import TokenExpired
from okta_oauth2.middleware import OktaMiddleware
from okta_oauth2.tests.utils import build_id_token, update_okta_settings


def test_no_token_redirects_to_login(rf):
    """
    If there's no token in the session then we should be
    redirecting to the login.
    """
    request = rf.get("/")
    request.session = {}
    mw = OktaMiddleware(Mock(return_value=HttpResponse()))
    response = mw(request)
    assert response.status_code == 302
    assert response.url == reverse("okta_oauth2:login")


def test_invalid_token_redirects_to_login(rf):
    """
    It there's a token but it's invalid we should be
    redirecting to the login.
    """
    request = rf.get("/")
    request.COOKIES["okta-oauth-nonce"] = "123456"
    request.session = {"tokens": {}}
    mw = OktaMiddleware(Mock(return_value=HttpResponse()))
    response = mw(request)
    assert response.status_code == 302
    assert response.url == reverse("okta_oauth2:login")


def test_valid_token_returns_response(rf):
    """
    If we have a valid token we should be returning the normal
    response from the middleware.
    """

    nonce = "123456"
    # We're building a token here that we know will be valid
    token = build_id_token(nonce=nonce)

    with patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        request = rf.get("/")
        request.COOKIES["okta-oauth-nonce"] = nonce
        request.session = {"tokens": {"id_token": token}}
        mw = OktaMiddleware(Mock(return_value=HttpResponse()))
        response = mw(request)
        assert response.status_code == 200


def test_token_expired_triggers_refresh(rf):
    """
    Test that an expired token triggers
    an attempt at refreshing the token.
    """
    raises_token_expired = Mock()
    raises_token_expired.side_effect = TokenExpired

    with patch(
        "okta_oauth2.tokens.TokenValidator.validate_token", raises_token_expired
    ), patch("okta_oauth2.tokens.TokenValidator.tokens_from_refresh_token"):

        request = rf.get("/")
        request.COOKIES["okta-oauth-nonce"] = "123456"
        request.session = {
            "tokens": {
                "id_token": "imanexpiredtoken",
                "refresh_token": "imsorefreshing",
            }
        }
        mw = OktaMiddleware(Mock(return_value=HttpResponse()))
        response = mw(request)
        assert response.status_code == 200


def test_token_expired_triggers_refresh_with_no_refresh(rf):
    """
    Test that an expired token triggers
    an attempt at refreshing the token. In this situation we
    don't have a refresh token so we should be redirecting back
    to login.
    """
    raises_token_expired = Mock()
    raises_token_expired.side_effect = TokenExpired

    with patch(
        "okta_oauth2.tokens.TokenValidator.validate_token", raises_token_expired
    ), patch("okta_oauth2.tokens.TokenValidator.tokens_from_refresh_token"):

        request = rf.get("/")
        request.COOKIES["okta-oauth-nonce"] = "123456"
        request.session = {"tokens": {"id_token": "imanexpiredtoken"}}
        mw = OktaMiddleware(Mock(return_value=HttpResponse()))
        response = mw(request)
        assert response.status_code == 302
        assert response.url == reverse("okta_oauth2:login")


def test_middleware_allows_public_url(settings, rf):
    """
    A URL that has been defined as a public url
    should just pass through our middleware.
    """
    settings.OKTA_AUTH = update_okta_settings(
        settings.OKTA_AUTH, "PUBLIC_NAMED_URLS", ("named-url",)
    )
    request = rf.get("/named/")
    request.session = {}
    mw = OktaMiddleware(Mock(return_value=HttpResponse()))
    response = mw(request)
    assert response.status_code == 200


def test_unauthorized_post_returns_401(settings, rf):
    """
    redirecting a POST is bad form so just return
    a 401 Unauthorized response if no token is there.
    """
    request = rf.post("/named/")
    request.session = {}
    mw = OktaMiddleware(Mock(return_value=HttpResponse()))
    response = mw(request)
    assert response.status_code == 401
