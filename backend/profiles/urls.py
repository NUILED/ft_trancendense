
from django.urls import re_path 
from .views import *
from django.contrib import admin

urlpatterns = [
    re_path('signup', Sign_upView.as_view()),
    re_path('login', LoginView.as_view()),
    re_path('logout', LogoutView.as_view()),
    re_path('user_info', Get_user_info.as_view()),
    re_path('up_user', Update_user_info.as_view()),
    re_path('oauth', SocialAuth.as_view()),
    re_path('socialauth', SocialAuthverify.as_view()),
]