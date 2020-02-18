# Create your models here.
from __future__ import unicode_literals

# from django.db import models
import requests
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
        except (AttributeError, KeyError):
            raise ImproperlyConfigured("Missing Okta authentication settings")


class DiscoveryDocument:
    # Find the OIDC metadata through discovery
    def __init__(self, issuer_uri):
        r = requests.get(issuer_uri + "/.well-known/openid-configuration")
        self.json = r.json()

    def getJson(self):
        return self.json


class TokenManager:
    def __init__(self):
        self.idToken = None
        self.accessToken = None
        self.claims = None

    def set_id_token(self, token):
        self.idToken = token

    def set_access_token(self, token):
        self.accessToken = token

    def set_claims(self, claims):
        self.claims = claims

    def getJson(self):
        response = {}
        if self.idToken:
            response["idToken"] = self.idToken

        if self.accessToken:
            response["accessToken"] = self.accessToken

        if self.claims:
            response["claims"] = self.claims
        return response
