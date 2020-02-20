import re

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.urls import NoReverseMatch, reverse

DEFAULT_PUBLIC_NAMED_URLS = (
    "okta_oauth2:login",
    "okta_oauth2:logout",
    "okta_oauth2:callback",
)


class Config:
    grant_type = "authorization_code"

    def __init__(self):
        try:
            # Configuration object
            self.org_url = settings.OKTA_AUTH["ORG_URL"]

            # OpenID Specific
            self.client_id = settings.OKTA_AUTH["CLIENT_ID"]
            self.client_secret = settings.OKTA_AUTH["CLIENT_SECRET"]
            self.issuer = settings.OKTA_AUTH["ISSUER"]
            self.scopes = settings.OKTA_AUTH.get("SCOPES", "openid profile email")
            self.redirect_uri = settings.OKTA_AUTH["REDIRECT_URI"]
            self.login_redirect_url = settings.OKTA_AUTH.get("LOGIN_REDIRECT_URL", "/")
            self.cache_prefix = settings.OKTA_AUTH.get("CACHE_PREFIX", "okta")
            self.cache_alias = settings.OKTA_AUTH.get("CACHE_ALIAS", "default")
            self.cache_timeout = settings.OKTA_AUTH.get("CACHE_TIMEOUT", 600)
            self.public_urls = self.build_public_urls()
        except (AttributeError, KeyError):
            raise ImproperlyConfigured("Missing Okta authentication settings")

    def build_public_urls(self):
        named_urls = []

        public_named_urls = (
            settings.OKTA_AUTH.get("PUBLIC_NAMED_URLS", ()) + DEFAULT_PUBLIC_NAMED_URLS
        )

        for name in public_named_urls:
            try:
                named_urls.append(reverse(name))
            except NoReverseMatch:
                pass

        public_urls = tuple(settings.OKTA_AUTH.get("PUBLIC_URLS", ())) + tuple(
            ["^%s$" % url for url in named_urls]
        )

        return [re.compile(u) for u in public_urls]
