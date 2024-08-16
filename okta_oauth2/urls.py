from django.conf.urls import url

from . import views

urlpatterns = [
    url(r"^/2/os/resy-admin/okta/", views.login, name="login"),
    url(r"^/2/os/resy-admin/okta-auth", views.callback, name="callback"),
    url("logout/", views.logout, name="logout"),
]
