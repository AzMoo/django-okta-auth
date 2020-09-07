from http.cookies import SimpleCookie
from unittest.mock import Mock, patch

from django.test import Client, override_settings
from django.urls import reverse


@override_settings(MIDDLEWARE=[])
def test_callback_without_messages():
    """
    The okta callback function should
    return a 500 with the error message from okta if
    the messages framework is not enabled.
    """
    c = Client()

    response = c.get(
        reverse("okta_oauth2:callback"),
        {
            "error": "invalid_scope",
            "error_description": "One or more scopes are not "
            "configured for the authorization server resource.",
        },
    )

    assert response.status_code == 500
    assert (
        response.content == b"One or more scopes are not configured for "
        b"the authorization server resource."
    )


def test_callback_redirects_on_error(settings):
    """
    The okta callback function should set a message
    and return a redirect if it gets an error.
    """

    # We need to set up django messages to actually set a message.
    settings.INSTALLED_APPS = settings.INSTALLED_APPS + ("django.contrib.messages",)
    settings.MIDDLEWARE = (
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    )
    settings.TEMPLATES = [
        {
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "DIRS": [],
            "APP_DIRS": True,
            "OPTIONS": {
                "context_processors": [
                    # Django builtin
                    "django.template.context_processors.debug",
                    "django.template.context_processors.media",
                    "django.template.context_processors.request",
                    "django.contrib.auth.context_processors.auth",
                    "django.contrib.messages.context_processors.messages",
                ]
            },
        }
    ]

    c = Client()

    response = c.get(
        reverse("okta_oauth2:callback"),
        {
            "error": "invalid_scope",
            "error_description": "One or more scopes are not configured"
            " for the authorization server resource.",
        },
    )

    assert response.status_code == 302
    assert response.url == reverse("okta_oauth2:login")


def test_callback_success(settings, django_user_model):
    """
    the callback method should authenticate successfully with
    an auth_code and nonce. We have to fake this because we can't hit
    okta with a fake auth code.
    """

    settings.MIDDLEWARE = ("django.contrib.sessions.middleware.SessionMiddleware",)

    nonce = "123456"

    user = django_user_model.objects.create_user("testuser", "testuser@example.com")

    with patch(
        "okta_oauth2.backend.TokenValidator.tokens_from_auth_code",
        Mock(return_value=(user, None)),
    ):
        c = Client()

        c.cookies = SimpleCookie(
            {"okta-oauth-state": "cookie-state", "okta-oauth-nonce": nonce}
        )

        response = c.get(
            reverse("okta_oauth2:callback"), {"code": "123456", "state": "cookie-state"}
        )

        assert response.status_code == 302
        assert response.url == "/"


def test_login_view(client):
    response = client.get(reverse("okta_oauth2:login"))
    assert response.status_code == 200
    assert "config" in response.context


def test_login_view_deletes_cookies(client):
    client.cookies = SimpleCookie(
        {"okta-oauth-state": "cookie-state", "okta-oauth-nonce": "123456"}
    )

    response = client.get(reverse("okta_oauth2:login"))

    assert response.status_code == 200
    assert response.cookies["okta-oauth-state"].value == ""
    assert (
        response.cookies["okta-oauth-state"]["expires"]
        == "Thu, 01 Jan 1970 00:00:00 GMT"
    )
    assert response.cookies["okta-oauth-nonce"].value == ""
    assert (
        response.cookies["okta-oauth-nonce"]["expires"]
        == "Thu, 01 Jan 1970 00:00:00 GMT"
    )


def test_callback_rejects_post(client):
    response = client.post(reverse("okta_oauth2:callback"))
    assert response.status_code == 400


def test_invalid_states_is_a_bad_request(client):
    client.cookies = SimpleCookie(
        {"okta-oauth-state": "cookie-state", "okta-oauth-nonce": "nonce"}
    )

    response = client.get(
        reverse("okta_oauth2:callback"), {"code": "123456", "state": "wrong-state"}
    )

    assert response.status_code == 400


def test_failed_authentication_redirects_to_login(client, settings, django_user_model):
    settings.MIDDLEWARE = ("django.contrib.sessions.middleware.SessionMiddleware",)

    nonce = "123456"

    # Creating a user to make sure there's actually one that *could* be returned.
    django_user_model.objects.create_user("testuser", "testuser@example.com")

    with patch("okta_oauth2.views.authenticate", Mock(return_value=None)):
        c = Client()

        c.cookies = SimpleCookie(
            {"okta-oauth-state": "cookie-state", "okta-oauth-nonce": nonce}
        )

        response = c.get(
            reverse("okta_oauth2:callback"), {"code": "123456", "state": "cookie-state"}
        )

        assert response.status_code == 302
        assert response.url == reverse("okta_oauth2:login")


def test_logout_view_returns_200(client, settings):
    settings.MIDDLEWARE = ("django.contrib.sessions.middleware.SessionMiddleware",)

    response = client.get(reverse("okta_oauth2:logout"))
    assert response.status_code == 302
    assert response.url == reverse("okta_oauth2:login")
