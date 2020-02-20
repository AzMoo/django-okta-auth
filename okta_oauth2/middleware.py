from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse

from .conf import Config
from .tokens import TokenValidator

config = Config()


class OktaMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if self.is_public_url(request.path_info):
            # We don't need tokens for public url's so just do nothing
            print("THIS IS A PUBLIC URL")
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

        try:
            validator = TokenValidator(config)
            validator.validate_token(
                request.session["tokens"]["access_token"],
                request.COOKIES["okta-oauth-nonce"],
            )
        except (ValueError, KeyError):
            return HttpResponseRedirect(reverse("okta_oauth2:login"))

        response = self.get_response(request)

        return response

    def is_public_url(self, url):
        return any(public_url.match(url) for public_url in config.public_urls)
