from django.conf.urls import url

from . import views

urlpatterns = [
    url(r"^login/$", views.login_view, name="login"),
    url(r"^oauth2/callback/$", views.callback, name="callback"),
    url(r"^logout/$", views.logout_view, name="logout"),
]
