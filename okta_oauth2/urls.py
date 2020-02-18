from django.conf.urls import url

from . import views

urlpatterns = [
    url(r"^$", views.home, name="home"),
    url(r"^login", views.login_view, name="login"),
    url(r"^oauth2/callback", views.callback, name="callback"),
    url(r"^userinfo", views.userinfo, name="userinfo"),
    url(r"^introspect", views.introspect, name="introspect"),
    url(r"^revocation", views.revocation, name="revocation"),
    url(r"^logout/", views.logout_view, name="logout"),
]
