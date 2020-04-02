from django.test import Client
from django.urls import reverse


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
