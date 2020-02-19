import logging

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpResponseBadRequest, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import reverse
from django.urls.exceptions import NoReverseMatch

from . import Config
from .decorators import okta_login_required

# GLOBALS
config = Config()

logger = logging.getLogger(__name__)


def login_view(request):
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

    login(request, user)

    try:
        redirect_url = reverse(config.login_redirect_url)
    except NoReverseMatch:
        redirect_url = config.login_redirect_url

    return redirect(redirect_url)


@login_required(redirect_field_name=None)
@okta_login_required
def logout_view(request):
    logout(request)
    return HttpResponseRedirect(reverse("okta_oauth2:login"))


def _get_user_by_username(username):
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return None
    return user


def _validate_user(claims):
    # Create user for django session
    user = _get_user_by_username(claims["email"])
    if user is None:
        # Create user
        user = User.objects.create_user(username=claims["email"], email=claims["email"])
    else:
        logger.debug("User exists")

    return user


def _delete_cookies(response):
    # The Okta Signin Widget/Javascript SDK aka "Auth-JS" automatically generates
    # state and nonce and stores them in cookies. Delete authJS/widget cookies
    response.set_cookie("okta-oauth-state", "", max_age=1)
    response.set_cookie("okta-oauth-nonce", "", max_age=1)
    response.set_cookie("okta-oauth-redirect-params", "", max_age=1)
