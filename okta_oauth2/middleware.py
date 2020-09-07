import logging

from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse

from .conf import Config
from .exceptions import InvalidToken, MissingAuthTokens
from .tokens import validate_tokens

logger = logging.getLogger(__name__)


class OktaMiddleware:
    """
    Middleware to validate JWT tokens set by Okta for authentication.
    """

    def __init__(self, get_response):
        self.config = Config()
        self.get_response = get_response

    def __call__(self, request):
        logger.debug("Entering Okta Middleware")

        if self.is_public_url(request.path_info):
            # We don't need tokens for public url's so just do nothing
            return self.get_response(request)

        try:
            validate_tokens(self.config, request)
        except MissingAuthTokens:
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
        except InvalidToken as e:
            logger.debug("Invalid token: %s", str(e))
            return HttpResponseRedirect(reverse("okta_oauth2:login"))

        response = self.get_response(request)

        return response

    def is_public_url(self, url):
        return any(public_url.match(url) for public_url in self.config.public_urls)
