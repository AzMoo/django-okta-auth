import json
import logging

from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import reverse

from .decorators import okta_login_required
from .models import Config, TokenManager
from .tokens import TokenValidator

# GLOBALS
config = Config()

logger = logging.getLogger(__name__)


def get_context(request):
    context = {"active": True}
    if "tokens" in request.session:
        context["tokens"] = request.session["tokens"]
        if "claims" in request.session["tokens"]:
            context["claims"] = json.dumps(
                request.session["tokens"]["claims"], sort_keys=True, indent=4
            )

    if "userInfo" in request.session:
        context["userInfo"] = request.session["userInfo"]

    if "introspect" in request.session:
        context["introspect"] = request.session["introspect"]

    if "revocation" in request.session:
        context["revocation"] = request.session["revocation"]

    return context


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
    def _token_request(auth_code, nonce):
        # authorization_code flow. Exchange the auth_code
        # for id_token and/or access_token
        user = None

        token_manager = TokenManager()
        validator = TokenValidator(config)
        tokens = validator.call_token_endpoint(auth_code)

        if tokens is not None:
            if "id_token" in tokens:
                # Perform token validation
                claims = validator.validate_token(tokens["id_token"], nonce)

                if claims:
                    token_manager.set_id_token(tokens["id_token"])
                    token_manager.set_claims(claims)
                    user = _validate_user(claims)

            if "access_token" in tokens:
                token_manager.set_access_token(tokens["access_token"])

        return user, token_manager.getJson()

    if request.POST:
        return HttpResponse({"error": "Endpoint not supported"})
    else:
        code = request.GET["code"]
        state = request.GET["state"]

        # Get state and nonce from cookie
        cookie_state = request.COOKIES["okta-oauth-state"]
        cookie_nonce = request.COOKIES["okta-oauth-nonce"]

        # Verify state
        if state != cookie_state:
            raise Exception("Value {} does not match the assigned state".format(state))
            return HttpResponseRedirect(reverse("login"))

        user, token_manager_json = _token_request(code, cookie_nonce)
        if user is None:
            return redirect("/login")
        else:
            login(request, user)

        request.session["tokens"] = token_manager_json
        return redirect("/")


# @login_required(redirect_field_name=None)
# @okta_login_required
# def revocation(request):
#     # Calls the revocation endpoint for revoking the accessToken
#     if request.POST:

#         access_token = request.POST.get("accessToken")

#         discovery_doc = DiscoveryDocument(config.issuer).getJson()

#         revocation = call_revocation(discovery_doc["issuer"], access_token, config)

#         if revocation is None:
#             request.session["revocation"] = "Access Token Revoked"
#         else:
#             request.session["revocation"] = json.dumps(revocation, indent=4)

#     return HttpResponseRedirect(reverse("home"))


# @login_required(redirect_field_name=None)
# @okta_login_required
# def introspect(request):
#     # Calls the introspect endpoint for checking the accessToken

#     if request.POST:

#         access_token = request.POST.get("accessToken")

#         discovery_doc = DiscoveryDocument(config.issuer).getJson()

#         introspect = call_introspect(discovery_doc["issuer"], access_token, config)

#         if introspect is not None:
#             request.session["introspect"] = json.dumps(introspect, indent=4)

#     return HttpResponseRedirect(reverse("home"))


# @login_required(redirect_field_name=None)
# @okta_login_required
# def userinfo(request):
#     # Calls userInfo endpoint with accessToken

#     if request.POST:
#         # Build token request
#         access_token = request.POST.get("accessToken")

#         # Send request
#         userInfo = call_userinfo_endpoint(config.issuer, access_token)

#         if userInfo is not None:
#             request.session["userInfo"] = json.dumps(userInfo, indent=4)

#     return HttpResponseRedirect(reverse("home"))


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
