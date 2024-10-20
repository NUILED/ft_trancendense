
from django.urls import path 
from .views import *
from django.contrib import admin

urlpatterns = [
    path('signup', Sign_upView.as_view()),
    path('login', LoginView.as_view()),
    path('logout', LogoutView.as_view()),
    path('user_info', Get_user_info.as_view()),
    path('up_user', Update_user_info.as_view()),
    path('oauth', SocialAuth.as_view()),
    path('socialauth', SocialAuthverify.as_view()),
    path('verify_token', VerifyToken.as_view()),
]