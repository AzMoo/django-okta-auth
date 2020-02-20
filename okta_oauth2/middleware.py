from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse

from .conf import Config
from .exceptions import InvalidToken, TokenExpired
from .tokens import TokenValidator

config = Config()


class OktaMiddleware:
    """
    Middleware to validate JWT tokens set by Okta for authentication.


    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if self.is_public_url(request.path_info):
            # We don't need tokens for public url's so just do nothing
            return self.get_response(request)

        if "tokens" not in request.session:
            # If we don't have any tokens then we want to just deny straight
            # up. We should always have tokens in the session when we're not
            # requesting a public view.
            if request.method == "POST":
                # Posting shouldn't redirect, it should just say no.
                response = HttpResponse()
                response.status_code = 401
                return response
            # Take us to the login so we can get some tokens.
            return HttpResponseRedirect(reverse("okta_oauth2:login"))

        validator = TokenValidator(config, request.COOKIES["okta-oauth-nonce"], request)

        try:
            try:
                validator.validate_token(request.session["tokens"]["id_token"])
            except TokenExpired:
                if "refresh_token" in request.session["tokens"]:
                    validator.tokens_from_refresh_token(
                        request.session["tokens"]["refresh_token"]
                    )
                else:
                    raise InvalidToken
        except (InvalidToken, KeyError):
            return HttpResponseRedirect(reverse("okta_oauth2:login"))

        response = self.get_response(request)

        return response

    def is_public_url(self, url):
        return any(public_url.match(url) for public_url in config.public_urls)
