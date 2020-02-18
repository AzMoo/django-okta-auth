Django Okta Auth
================

This is pretty much a direct rip-off of https://github.com/zeekhoo-okta/okta-django-samples

Settings should be specified in your django `settings.py as follows:

    OKTA_AUTH = {
        "ORG_URL": "https://your-org.okta.com/",
        "ISSUER": "https://your-org.okta.com/oauth2/default",
        "CLIENT_ID": "yourclientid",
        "CLIENT_SECRET": "yourclientsecret",
        "SCOPES": "openid profile email", # this is the default and can be omitted
        "REDIRECT_URI": "http://localhost:8000/oauth2/callback"
    }
