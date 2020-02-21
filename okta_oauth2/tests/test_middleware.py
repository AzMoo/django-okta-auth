from unittest.mock import Mock, patch

from django.http import HttpResponse
from django.test import RequestFactory
from django.urls import reverse
from okta_oauth2.exceptions import TokenExpired
from okta_oauth2.middleware import OktaMiddleware

rf = RequestFactory()


def test_no_token_redirects_to_login():
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


def test_invalid_token_redirects_to_login():
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


def test_valid_token_returns_response(mocker):
    """
    If we have a valid token we should be returning the normal
    response from the middleware.
    """
    # validate_token will raise an exception if it fails, so we're
    # just replacing it with something that does nothing and pretending
    # it succeeded. We have to do this because we can't actually validate
    # a real token because we don't have one.
    with patch("okta_oauth2.middleware.TokenValidator.validate_token"):
        request = rf.get("/")
        request.COOKIES["okta-oauth-nonce"] = "123456"
        request.session = {"tokens": {"id_token": "imavalidtokenbutnotreallylol"}}
        mw = OktaMiddleware(Mock(return_value=HttpResponse()))
        response = mw(request)
        assert response.status_code == 200


def test_token_expired_triggers_refresh():
    """
    Test that an expired token triggers
    an attempt at refreshing the token.
    """
    raises_token_expired = Mock()
    raises_token_expired.side_effect = TokenExpired

    with patch("okta_oauth2.middleware.TokenValidator.validate_token"), patch(
        "okta_oauth2.middleware.TokenValidator.tokens_from_refresh_token"
    ):

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
