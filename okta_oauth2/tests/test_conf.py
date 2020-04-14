import re

import pytest
from django.core.exceptions import ImproperlyConfigured
from okta_oauth2.conf import Config
from okta_oauth2.tests.utils import update_okta_settings


def test_conf_raises_error_if_no_settings(settings):
    """
    if there's no OKTA_AUTH in settings then we should
    be raising an ImproperlyConfigured exception.
    """
    del settings.OKTA_AUTH
    with pytest.raises(ImproperlyConfigured):
        Config()


def test_public_named_urls_are_built(settings):
    """
    We should have reversed url regexes to match against
    in our config objects.
    """
    settings.OKTA_AUTH = update_okta_settings(
        settings.OKTA_AUTH, "PUBLIC_NAMED_URLS", ("named-url",)
    )
    config = Config()
    assert config.public_urls == [
        re.compile("^/named/$"),
        re.compile("^/accounts/login/$"),
        re.compile("^/accounts/logout/$"),
        re.compile("^/accounts/oauth2/callback/$"),
    ]


def test_invalid_public_named_urls_are_ignored(settings):
    """
    We don't want to crash if our public named urls don't
    exist, instead just skip it.
    """
    settings.OKTA_AUTH = update_okta_settings(
        settings.OKTA_AUTH, "PUBLIC_NAMED_URLS", ("not-a-valid-url",)
    )
    config = Config()
    assert config.public_urls == [
        re.compile("^/accounts/login/$"),
        re.compile("^/accounts/logout/$"),
        re.compile("^/accounts/oauth2/callback/$"),
    ]
