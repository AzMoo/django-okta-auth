import base64
import time

import jwt as jwt_python
import requests
from django.contrib.auth import get_user_model
from django.core.cache import caches
from jose import jws, jwt
from jose.exceptions import JWSError, JWTError

from .exceptions import (
    InvalidClientID,
    InvalidTokenSignature,
    IssuerDoesNotMatch,
    NonceDoesNotMatch,
    TokenExpired,
    TokenRequestFailed,
    TokenTooFarAway,
)

UserModel = get_user_model()


class DiscoveryDocument:
    # Find the OIDC metadata through discovery
    def __init__(self, issuer_uri):
        r = requests.get(issuer_uri + "/.well-known/openid-configuration")
        self.json = r.json()

    def getJson(self):
        return self.json


class TokenValidator:
    _discovery_document = None

    def __init__(self, config, nonce, request):
        self.config = config
        self.cache = caches[config.cache_alias]
        self.cache_key = "{}-keys".format(config.cache_prefix)
        self.request = request
        self.nonce = nonce

    @property
    def discovery_document(self):
        if self._discovery_document is None:
            self._discovery_document = DiscoveryDocument(self.config.issuer)
        return self._discovery_document

    def tokens_from_auth_code(self, code):
        data = {"grant_type": "authorization_code", "code": str(code)}

        result = self.call_token_endpoint(data)
        return self.handle_token_result(result)

    def tokens_from_refresh_token(self, refresh_token):
        data = {"grant_type": "refresh_token", "refresh_token": str(refresh_token)}

        result = self.call_token_endpoint(data)
        return self.handle_token_result(result)

    def handle_token_result(self, token_result):
        tokens = {}

        if token_result is None or "id_token" not in token_result:
            return None, tokens

        claims = self.validate_token(token_result["id_token"])

        if claims:
            tokens["id_token"] = token_result["id_token"]
            tokens["claims"] = claims

            try:
                user = UserModel._default_manager.get_by_natural_key(claims["email"])
            except UserModel.DoesNotExist:
                if (
                    self.config.superuser_group
                    and "groups" in claims
                    and self.config.superuser_group in claims["groups"]
                ):
                    user = UserModel._default_manager.create_user(
                        username=claims["email"],
                        email=claims["email"],
                        is_staff=True,
                        is_superuser=True,
                    )
                else:
                    user = UserModel._default_manager.create_user(
                        username=claims["email"], email=claims["email"]
                    )

        if "access_token" in token_result:
            tokens["access_token"] = token_result["access_token"]

        if "refresh_token" in token_result:
            tokens["refresh_token"] = token_result["refresh_token"]

        if user:
            self.request.session["tokens"] = tokens
            self.request.session.modified = True

        return user, tokens

    def call_token_endpoint(self, endpoint_data):
        """ Call /token endpoint
            Returns access_token, id_token, and/or refresh_token
        """
        discovery_doc = self.discovery_document.getJson()
        token_endpoint = discovery_doc["token_endpoint"]

        basic_auth_str = "{0}:{1}".format(
            self.config.client_id, self.config.client_secret
        )
        authorization_header = base64.b64encode(basic_auth_str.encode())
        header = {
            "Authorization": "Basic: " + authorization_header.decode("utf-8"),
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {"scope": self.config.scopes, "redirect_uri": self.config.redirect_uri}

        data.update(endpoint_data)
        # Send token request
        r = requests.post(token_endpoint, headers=header, params=data)
        response = r.json()

        # Return object
        result = {}
        if "error" not in response:
            if "access_token" in response:
                result["access_token"] = response["access_token"]
            if "id_token" in response:
                result["id_token"] = response["id_token"]
            if "refresh_token" in response:
                result["refresh_token"] = response["refresh_token"]
        else:
            raise TokenRequestFailed(
                response["error"], response.get("error_description", None)
            )

        return result if len(result.keys()) > 0 else None

    def request_jwks(self):
        discovery_doc = self.discovery_document.getJson()
        r = requests.get(discovery_doc["jwks_uri"])
        return r.json()

    def _jwks(self, kid):
        """
            Internal:
                Fetch public key from jwks_uri and caches it until the key rotates
            :param kid: "key Id"
            :return: key from jwks_uri having the kid key
        """

        cached_keys = self.cache.get(self.cache_key) or []

        for key in cached_keys:
            if key["kid"] == kid:
                return key

        # lookup the key from jwks_uri if key is not in cache
        jwks = self.request_jwks()

        for key in jwks["keys"]:
            if kid == key["kid"]:
                cached_keys.append(key)
                self.cache.set(self.cache_key, cached_keys, self.config.cache_timeout)
                return key

        return None

    def validate_token(self, token):
        """
        Validate token
        (Taken from
        http://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation)
        """

        """ Step 1
            If encrypted, decrypt it using the keys and algorithms specified
            in the meta_data

            If encryption was negotiated but not provided, REJECT

            Skipping Okta has not implemented encrypted JWT
        """

        decoded_token = jwt_python.decode(token, verify=False)

        dirty_alg = jwt.get_unverified_header(token)["alg"]
        dirty_kid = jwt.get_unverified_header(token)["kid"]

        key = self._jwks(dirty_kid)
        if key:
            # Validate the key using jose-jws
            try:
                jws.verify(token, key, algorithms=[dirty_alg])
            except (JWTError, JWSError) as err:
                raise InvalidTokenSignature("Invalid token signature") from err
        else:
            raise InvalidTokenSignature("Unable to fetch public signing key")

        """ Step 2
            Issuer Identifier for the OpenID Provider (which is typically
            obtained during Discovery) MUST exactly match the value of the
            iss (issuer) Claim.
            Redundant, since we will validate in Step 3, the "iss" claim matches
            host we requested the token from
        """

        if decoded_token["iss"] != self.config.issuer:
            """ Step 3
                Client MUST validate:
                    aud (audience) contains the same `client_id` registered
                    iss (issuer) identified as the aud (audience)
                    aud (audience) Claim MAY contain an array with more than one
                    element (Currently NOT IMPLEMENTED by Okta)
                The ID Token MUST be rejected if the ID Token does not list the
                Client as a valid audience, or if it contains additional audiences
                not trusted by the Client.
            """
            raise IssuerDoesNotMatch("Issuer does not match")

        if decoded_token["aud"] != self.config.client_id:
            raise InvalidClientID("Audience does not match client_id")

        """ Step 6 : TLS server validation not implemented by Okta
            If ID Token is received via direct communication between Client and
            Token Endpoint, TLS server validation may be used to validate the
            issuer in place of checking token
            signature. MUST validate according to JWS algorithm specialized in JWT
            alg Header. MUST use keys provided.
        """

        """ Step 7
            The alg value SHOULD default to RS256 or sent in
            id_token_signed_response_alg param during Registration

            We don't need to test this. Okta always signs in RS256
        """

        """ Step 8 : Not implemented due to Okta configuration

            If JWT alg Header uses MAC based algorithm (HS256, HS384, etc) the
            octets of UTF-8 of the client_secret corresponding to the client_id
            are contained in the aud (audience) are used to validate the signature.
            For MAC based, if aud is multi-valued or if azp value is different
            than aud value - behavior is unspecified.
        """

        if decoded_token["exp"] < int(time.time()):
            """ Step 9
                The current time MUST be before the time represented by exp
            """
            raise TokenExpired

        if decoded_token["iat"] < (int(time.time()) - 100000):
            """ Step 10 - Defined 'too far away time' : approx 24hrs
                The iat can be used to reject tokens that were issued too far away
                from current time, limiting the time that nonces need to be stored
                to prevent attacks.
            """
            raise TokenTooFarAway("iat too far in the past ( > 1 day)")

        if self.nonce is not None and "nonce" in decoded_token:
            """ Step 11
                If a nonce value is sent in the Authentication Request,
                a nonce MUST be present and be the same value as the one
                sent in the Authentication Request. Client SHOULD check for
                nonce value to prevent replay attacks.
            """
            if self.nonce != decoded_token["nonce"]:
                raise NonceDoesNotMatch(
                    "nonce value does not match Authentication Request nonce"
                )

        """ Step 12:  Not implemented by Okta
            If acr was requested, check that the asserted Claim Value is appropriate
        """

        """ Step 13
            If auth_time was requested, check claim value and request
            re-authentication if too much time elapsed

            We relax this requirement during jwt validation. The Okta Session
            should be handled inside Okta

            See https://developer.okta.com/docs/api/resources/sessions
        """

        return decoded_token
