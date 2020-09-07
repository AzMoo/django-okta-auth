# Django Okta Auth

## Overview
Django Okta Auth is a library that acts as a client for the Okta OpenID Connect provider.

The library provides a set of views for login, logout and callback, an auth backend for authentication, a middleware for token verification in requests, and a decorator that can be selectively applied to individual views.

It's heavily influenced by [okta-django-samples](https://github.com/zeekhoo-okta/okta-django-samples) but there's a few fundamental changes and further implementation of things like refresh tokens which weren't initially implemented.

This project is in no way affiliated with Okta.

## Installation

Install from PyPI:

    pip install django-okta-auth

## Configuration

### Install the App

Add `okta_oauth2.apps.OktaOauth2Config` to `INSTALLED_APPS`:

    INSTALLED_APPS = (
        ...,
        'okta_oauth2.apps.OktaOauth2Config',
        ...
    )

### Authentication Backend

You will need to install the authentication backend. This extends Django's default `ModelBackend` which uses the configured database for user storage, but overrides the `authenticate` method to accept the `auth_code` returned by Okta's `/authorize` API endpoint [as documented here](https://developer.okta.com/docs/reference/api/oidc/#authorize).  

The Authentication Backend should be configured as so:

    AUTHENTICATION_BACKENDS = ("okta_oauth2.backend.OktaBackend",)

### Using the middleware

You can use the middleware to check for valid tokens during ever refresh and automatically refresh tokens when they expire. By using the middleware you are defaulting to requiring authentication on all your views unless they have been marked as public in `PUBLIC_NAMED_URLS` or `PUBLIC_URLS`.

The order of middleware is important and the `OktaMiddleware` must be below the `SessionMiddleware` and `AuthenticationMiddleware` to ensure that the session and the user are both on the request:

    MIDDLEWARE = (
        'django.middleware.security.SecurityMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.common.CommonMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'django.middleware.clickjacking.XFrameOptionsMiddleware',
        'okta_oauth2.middleware.OktaMiddleware'
    )

### Using the decorator

The alternative to using the middleware is to selectively apply the `okta_oauth2.decorators.okta_login_required` decorator to views you wish to protect. When the view is accessed the decorator will check that valid tokens exist on the session, and if they don't then it will redirect to the login.

The decorator is applied to a view like so:

    from okta_oauth2.decorators import okta_login_required

    @okta_login_required
    def decorated_view(request):
        return HttpResponse("i am a protected view")

### Update urls<span></span>.py

Add the `django-okta-auth` views to your `urls.py`. This will provide the `login`, `logout` and `callback` views which are required by the login flows.

    from django.urls import include, path

    urlpatterns = [
        path('accounts/', include(("okta_oauth2.urls", "okta_oauth2"), namespace="okta_oauth2")),
    ]

### Setup your Okta Application

In the Okta admin console create your application with the following steps:

1. Click `Create New App`
2. Choose the `Web` platform
3. Choose the `OpenID Connect` Sign on method
4. Click the `Create` button
5. Give the application a name and choose a logo if desired
6. Add the URL to the login view as defined in the previous section, eg. `http://localhost:8000/accounts/login/`
7. Click the `Save` button
8. In the General Settings of the application click edit and check `Authorization Code` and the `Refresh Token` under `Allowed grant types`.
9. Save the settings
10. Take note of the `Client ID` and the `Client secret` in the Client Credentials for use in the next section. It is important to note that the `Client secret` is confidential and under no circumstances should be exposed publicly.

### Django Okta Settings

Django Okta Auth settings should be specified in your django `settings.py` as follows:

    OKTA_AUTH = {
        "ORG_URL": "https://your-org.okta.com/",
        "ISSUER": "https://your-org.okta.com/oauth2/default",
        "CLIENT_ID": "yourclientid",
        "CLIENT_SECRET": "yourclientsecret",
        "SCOPES": "openid profile email offline_access", # this is the default and can be omitted
        "REDIRECT_URI": "http://localhost:8000/oauth2/callback",
        "LOGIN_REDIRECT_URL": "/", # default
        "CACHE_PREFIX": "okta", # default
        "CACHE_ALIAS: "default", # default
        "PUBLIC_NAMED_URLS": (), # default
        "PUBLIC_URLS": (), # default
    }

### Login Template

The login view will render the `okta_oauth2/login.html` template. It will be passed the following information in the `config` template context variable:

    {
        "clientId": settings.OKTA_AUTH["CLIENT_ID"],
        "url": settings.OKTA_AUTH["ORG_URL"],
        "redirectUri": settings.OKTA_AUTH["REDIRECT_URI"],
        "scope": settings.OKTA_AUTH["SCOPES"],
        "issuer": settings.OKTA_AUTH["ISSUER"]
    }

The easiest way to use this is to implement the [Okta Sign-In Widget](https://developer.okta.com/code/javascript/okta_sign-in_widget/) in your template.

A minimal template for the login could be:

```html
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <script src="https://global.oktacdn.com/okta-signin-widget/3.1.3/js/okta-sign-in.min.js" type="text/javascript"></script>
        <link href="https://global.oktacdn.com/okta-signin-widget/3.1.3/css/okta-sign-in.min.css" type="text/css" rel="stylesheet"/>
    </head>
    <body>
        <div id="okta-login-container"></div>

        <script>
        var oktaSignIn = new OktaSignIn({
            logo: 'https://logo.clearbit.com/fakedetail.com',
            baseUrl: '{{config.url}}',
            clientId: '{{config.clientId}}',
            redirectUri: '{{config.redirectUri}}',
            authParams: {
                issuer: '{{config.issuer}}',
                responseType: ['code'],
                scopes: "{{config.scope}}".split(" ")
            },
        });
        </script>

    </body>
</html>
```

## Settings Reference

***ORG_URL***:

*str*. URL Okta provides for your organization account. This is the URL that you log in to for the admin panel, minus the `-admin`. eg, if your admin URL is https://myorg-admin.okta.com/ then your `ORG_URL` should be: https://myorg.okta.com/

***ISSUER***

*str*. This is the URL for your Authorization Server. If you're using the default authorization server then this will be: `https://{ORG_URL}/oauth2/default`

***CLIENT_ID***

*str*. The Client ID provided by your Okta Application.

***CLIENT_SECRET***

*str*. The Client Secret provided by your Okta Application.

***SCOPES***

*str*. The scopes requested from the OpenID Authorization server. At the very least this needs to be `"openid profile email"` but if you want to use refresh tokens you will need `"openid profile email offline_access"`. This is the default.

If you want Okta to manage your groups then you should also include `groups` in your scopes.

***REDIRECT_URI***

*str*. This is the URL to the `callback` view that the okta Sign-In Widget will redirect the browser to after the username and password have been authorized. If the directions in the `urls.py` section of the documentation were followed and your django server is running on `localhost:8000` then this will be: http://localhost:8000/accounts/callback/

***LOGIN_REDIRECT_URL***

*str*. This is the URL to redirect to from the `callback` after a successful login. Defaults to `/`.

***CACHE_PREFIX***

*str*. The application will utilise the django cache to store public keys requested from Okta in an effort to minimise network round-trips and speed up authorization. This setting will control the prefix for the cache keys. Defaults to `okta`.

***CACHE_ALIAS***

*str*. Specify which django cache should be utilised for storing public keys. Defaults to `default`.

***PUBLIC_NAMED_URLS***

*List[str]*. A list or tuple of URL names that should be accessible without tokens. If you add a URL in this setting the middleware won't check for tokens. Default is: `[]`

***PUBLIC_URLS***

*List[str]*. A list or tuple of URL regular expressions that should be accessible without tokens. If you add a regex in this setting the middleware won't check matching paths for tokens. Default is `[]`.

***SUPERUSER_GROUP***

*str*. Members of this group will be created with the django `is_staff` and `is_superuser` flags set.

***MANAGE_GROUPS***

*bool*. If true the authentication backend will manage django groups for you.

## License

MIT License

Copyright (c) 2020 Matt Magin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
