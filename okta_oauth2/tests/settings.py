SECRET_KEY = "imasecretlol"

DATABASES = {"default": {"NAME": "test.db", "ENGINE": "django.db.backends.sqlite3"}}

INSTALLED_APPS = (
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "okta_oauth2.apps.OktaOauth2Config",
)

OKTA_AUTH = {
    "ORG_URL": "https://test.okta.notreal/",
    "ISSUER": "https://test.okta.notreal/oauth2/default",
    "CLIENT_ID": "not-a-real-id",
    "CLIENT_SECRET": "not-a-real-secret",
    "REDIRECT_URI": "http://localhost:8000/accounts/callback/",
}

ROOT_URLCONF = "okta_oauth2.tests.urls"
