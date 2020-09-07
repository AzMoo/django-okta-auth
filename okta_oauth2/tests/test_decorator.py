from unittest.mock import Mock, patch

import pytest
from django.test import Client
from okta_oauth2.tests.utils import build_id_token


def test_decorator_prevents_unauthenticated_access(client: Client):
    """ If we're not authenticated we should return a redirect to the login """
    response = client.get("/decorated/")
    assert response.status_code == 302
    assert response.url == "/accounts/login/"


@pytest.mark.django_db
def test_decorator_allows_access_to_valid_token(client: Client):
    """
    If we have a valid token then we should allow access to the view.
    """
    nonce = "123456"
    token = build_id_token(nonce=nonce)

    client.cookies.load({"okta-oauth-nonce": nonce})

    session = client.session
    session["tokens"] = {"id_token": token}
    session.save()

    with patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        response = client.get("/decorated/")
        assert response.status_code == 200


@pytest.mark.django_db
def test_decorator_disallows_access_to_invalid_token(client: Client):
    """ When an invalid token is supplied the decorator should reject. """
    nonce = "123456"
    token = "notvalid"

    client.cookies.load({"okta-oauth-nonce": nonce})

    session = client.session
    session["tokens"] = {"id_token": token}
    session.save()

    with patch("okta_oauth2.tokens.TokenValidator._jwks", Mock(return_value="secret")):
        response = client.get("/decorated/")
        assert response.status_code == 302
        assert response.url == "/accounts/login/"
