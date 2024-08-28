from django.conf.urls import url

from . import views

urlpatterns = [
    url("okta/", views.login, name="login"),
    url("auth/", views.callback, name="callback"),
    url("logout/", views.logout, name="logout"),
]
