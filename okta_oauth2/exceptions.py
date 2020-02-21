class InvalidToken(Exception):
    """ Base exception for an invalid token """

    pass


class InvalidTokenSignature(InvalidToken):
    """ Token signatures doesn't validate """

    pass


class IssuerDoesNotMatch(InvalidToken):
    """ Token Issuer doesn't match expected issuer """

    pass


class InvalidClientID(InvalidToken):
    """ Token ClientID doesn't match expected Client ID """

    pass


class TokenExpired(InvalidToken):
    """ Token expiration time is in the past """

    pass


class TokenTooFarAway(InvalidToken):
    """ The received token is not valid until too far in the future. """

    pass


class NonceDoesNotMatch(InvalidToken):
    """ Token nonce does not match expected nonce """

    pass


class TokenRequestFailed(Exception):
    """ The request to the token api endpoint has failed. """

    pass
