from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from .conf import Config
from .tokens import TokenValidator

UserModel = get_user_model()

config = Config()


class OktaBackend(ModelBackend):
    def authenticate(self, request, auth_code=None, nonce=None):
        if auth_code is None or nonce is None:
            return
        user = None

        tokens = {}
        validator = TokenValidator(config)
        token_result = validator.call_token_endpoint(auth_code)

        if token_result is not None:
            if "id_token" in token_result:
                # Perform token validation
                claims = validator.validate_token(token_result["id_token"], nonce)

                if claims:
                    tokens["id_token"] = token_result["id_token"]
                    tokens["claims"] = claims

                    try:
                        user = UserModel._default_manager.get_by_natural_key(
                            claims["email"]
                        )
                    except UserModel.DoesNotExist:
                        user = UserModel._default_manager.create_user(
                            username=claims["email"], email=claims["email"]
                        )

            if "access_token" in token_result:
                tokens["access_token"] = token_result["access_token"]

        if user:
            request.session["tokens"] = tokens

        return user
