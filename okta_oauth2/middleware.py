import logging

from .conf import Config
from .tokens import validate_or_redirect

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

        redirect_response = validate_or_redirect(self.config, request)

        if redirect_response:
            return redirect_response

        return self.get_response(request)

    def is_public_url(self, url):
        return any(public_url.match(url) for public_url in self.config.public_urls)
