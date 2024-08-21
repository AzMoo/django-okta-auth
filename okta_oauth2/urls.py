from django.conf.urls import url

from . import views

urlpatterns = [
    url(r"^okta/", views.login, name="login"),
    url(r"^okta-auth/", views.callback, name="callback"),
    url("logout/", views.logout, name="logout"),
]
