
from django.urls import re_path 
from .views import Delete_user ,Sign_upView ,LoginView , CallBack ,Get_user_info ,Update_user_info ,\
    ConfirmEmailView ,LogoutView
from django.contrib import admin

urlpatterns = [
    re_path('signup', Sign_upView.as_view()),
    re_path('login', LoginView.as_view()),
    re_path('logout', LogoutView.as_view()),
    re_path('callback', CallBack.as_view()),
    re_path('user_info', Get_user_info.as_view()),
    re_path('up_user', Update_user_info.as_view()),
    re_path('del_user', Delete_user.as_view()),
    re_path('activate', ConfirmEmailView.as_view()),
    # re_path('get42token', Get42Tok.as_view()),
]