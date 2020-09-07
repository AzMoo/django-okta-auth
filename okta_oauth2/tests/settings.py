import os

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

AUTHENTICATION_BACKENDS = ("okta_oauth2.backend.OktaBackend",)

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "DIRS": [
            os.path.join(os.path.dirname(__file__), "templates"),
        ],
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
    },
]
