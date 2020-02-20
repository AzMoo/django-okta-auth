import logging

from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.http import HttpResponseBadRequest, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import reverse
from django.urls.exceptions import NoReverseMatch

from .conf import Config

logger = logging.getLogger(__name__)


def login(request):
    config = Config()

    okta_config = {
        "clientId": config.client_id,
        "url": config.org_url,
        "redirectUri": str(config.redirect_uri),
        "scope": config.scopes,
        "issuer": config.issuer,
    }
    response = render(request, "login.html", {"config": okta_config})

    _delete_cookies(response)

    return response


def callback(request):
    config = Config()

    if request.POST:
        return HttpResponseBadRequest("Method not supported")

    code = request.GET["code"]
    state = request.GET["state"]

    # Get state and nonce from cookie
    cookie_state = request.COOKIES["okta-oauth-state"]
    cookie_nonce = request.COOKIES["okta-oauth-nonce"]

    # Verify state
    if state != cookie_state:
        return HttpResponseBadRequest(
            "Value {} does not match the assigned state".format(state)
        )

    user = authenticate(request, auth_code=code, nonce=cookie_nonce)

    if user is None:
        return redirect(reverse("okta_oauth2:login"))

    auth_login(request, user)

    try:
        redirect_url = reverse(config.login_redirect_url)
    except NoReverseMatch:
        redirect_url = config.login_redirect_url

    return redirect(redirect_url)


def logout(request):
    auth_logout(request)
    return HttpResponseRedirect(reverse("okta_oauth2:login"))


def _delete_cookies(response):
    # The Okta Signin Widget/Javascript SDK aka "Auth-JS" automatically generates
    # state and nonce and stores them in cookies. Delete authJS/widget cookies
    response.set_cookie("okta-oauth-state", "", max_age=1)
    response.set_cookie("okta-oauth-nonce", "", max_age=1)
    response.set_cookie("okta-oauth-redirect-params", "", max_age=1)
