from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.login, name="login"),
    path("oauth2/callback/", views.callback, name="callback"),
    path("logout/", views.logout, name="logout"),
]
