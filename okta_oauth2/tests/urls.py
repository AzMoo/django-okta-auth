from django.http import HttpResponse
from django.urls import include, path
from okta_oauth2.decorators import okta_login_required


def test_view(request):
    return HttpResponse("not a real view")


@okta_login_required
def decorated_view(request):
    return HttpResponse("i am decorated")


urlpatterns = [
    path("", test_view),
    path("decorated/", decorated_view),
    path("named/", test_view, name="named-url"),
    path(
        "accounts/",
        include(("okta_oauth2.urls", "okta_oauth2"), namespace="okta_oauth2"),
    ),
]
