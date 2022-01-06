import re

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.urls import NoReverseMatch, reverse

# We can't check for tokens on these URL's
# because we won't have them.
DEFAULT_PUBLIC_NAMED_URLS = (
    "okta_oauth2:login",
    "okta_oauth2:logout",
    "okta_oauth2:callback",
)


class Config:
    def __init__(self):
        try:
            # Configuration object
            self.org_url = settings.OKTA_AUTH["ORG_URL"]
            # Make users in this okta group superusers
            self.superuser_group = settings.OKTA_AUTH.get("SUPERUSER_GROUP", None)
            # Make users in this okta group staff
            self.staff_group = settings.OKTA_AUTH.get("STAFF_GROUP", None)
            # Allow django-okta-auth to add groups
            self.manage_groups = settings.OKTA_AUTH.get("MANAGE_GROUPS", False)
            # In Okta there is a 100 AD group limit to the number of groups returned for
            # a user.  Also often you will create a custom group for your application.
            # To limit the number of AD Groups, I created a custom name and populated it 
            # using a regex to return only names like "app_XYZ_*"  Thus getting round the 
            # 100 name limit.  But we need to pass in the group_name if not the default.
            self.group_name = settings.OKTA_AUTH.get("GROUP_NAME", "groups")

            # OpenID Specific
            self.client_id = settings.OKTA_AUTH["CLIENT_ID"]
            self.client_secret = settings.OKTA_AUTH["CLIENT_SECRET"]
            self.issuer = settings.OKTA_AUTH["ISSUER"]
            self.scopes = settings.OKTA_AUTH.get(
                "SCOPES", "openid profile email offline_access"
            )
            self.redirect_uri = settings.OKTA_AUTH["REDIRECT_URI"]
            self.login_redirect_url = settings.OKTA_AUTH.get("LOGIN_REDIRECT_URL", "/")

            # Django Specific
            self.cache_prefix = settings.OKTA_AUTH.get("CACHE_PREFIX", "okta")
            self.cache_alias = settings.OKTA_AUTH.get("CACHE_ALIAS", "default")
            self.cache_timeout = settings.OKTA_AUTH.get("CACHE_TIMEOUT", 600)
            self.use_username = settings.OKTA_AUTH.get("USE_USERNAME", False)
            self.public_urls = self.build_public_urls()
            
            # Django User Model Mapping (To allow users to use custom Okta fields to map to Django)
            self.user_mapping_username = settings.OKTA_AUTH.get("USER_MAPPING_USERNAME", "email")
            self.user_mapping_email = settings.OKTA_AUTH.get("USER_MAPPING_EMAIL", "email")
            self.user_mapping_first_name = settings.OKTA_AUTH.get("USER_MAPPING_FIRST_NAME", "firstName")
            self.user_mapping_last_name = settings.OKTA_AUTH.get("USER_MAPPING_USERNAME", "lastName")
            
        except (AttributeError, KeyError):
            raise ImproperlyConfigured("Missing Okta authentication settings")

    def build_public_urls(self):
        named_urls = []

        # Get any user-specified named urls and concat the default named urls
        # so that we can reverse them all at once.
        public_named_urls = (
            settings.OKTA_AUTH.get("PUBLIC_NAMED_URLS", ()) + DEFAULT_PUBLIC_NAMED_URLS
        )

        for name in public_named_urls:
            try:
                named_urls.append(reverse(name))
            except NoReverseMatch:
                pass

        # Concatenate user-specified regex URL's with a tuple of reversed named
        # url's that have been converted to a regex, so we can use a regex
        # to match against a url in every case.
        public_urls = tuple(settings.OKTA_AUTH.get("PUBLIC_URLS", ())) + tuple(
            ["^%s$" % url for url in named_urls]
        )

        return [re.compile(u) for u in public_urls]
