from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


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
        except (AttributeError, KeyError):
            raise ImproperlyConfigured("Missing Okta authentication settings")
