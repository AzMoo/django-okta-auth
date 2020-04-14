from unittest.mock import Mock, patch

from okta_oauth2.backend import OktaBackend


def test_backend_authenticate_requires_code_and_nonce(rf):
    """
    the authenticate method on the custom backend requires both
    an auth code and a nonce. If either aren't provided then
    authenitcate should return None
    """
    backend = OktaBackend()
    assert backend.authenticate(rf) is None


def test_authenticate_returns_a_user(rf, django_user_model):
    """
    We can't do the real authentication but we do need to make sure a
    real user is returned from the backend authenticate method if the
    TokenValidator succeeds, so fake success and see what happens.
    """
    user = django_user_model.objects.create_user("testuser", "testuser@example.com")

    with patch(
        "okta_oauth2.backend.TokenValidator.tokens_from_auth_code",
        Mock(return_value=(user, None)),
    ):
        backend = OktaBackend()
        assert backend.authenticate(rf, auth_code="123456", nonce="imanonce") == user
