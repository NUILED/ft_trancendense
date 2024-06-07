from . import views
from django.urls import path

urlpatterns = [
    path('', views.index , name="index"),
    path('callback', views.callback , name="callback"),
    path('login', views.login , name="login"),
]