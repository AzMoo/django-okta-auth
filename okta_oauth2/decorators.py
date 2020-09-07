from functools import wraps

from .conf import Config
from .tokens import validate_or_redirect


def okta_login_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        config = Config()
        response = validate_or_redirect(config, request)
        if response:
            return response
        else:
            return view_func(request, *args, **kwargs)

    return _wrapped_view
