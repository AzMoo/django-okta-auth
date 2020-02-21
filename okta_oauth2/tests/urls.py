from django.http import HttpResponse
from django.urls import include, path


def test_view(request):
    return HttpResponse("not a real view")


urlpatterns = [
    path("", test_view),
    path(
        "accounts/",
        include(("okta_oauth2.urls", "okta_oauth2"), namespace="okta_oauth2"),
    ),
]
