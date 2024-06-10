
from django.urls import re_path 
from .views import Delete_user ,Sign_upView ,LoginView, Valid_Token, CallBack ,Get_user_info ,Update_user_info

urlpatterns = [
    re_path('signup', Sign_upView.as_view()),
    re_path('login', LoginView.as_view()),
    re_path('v_token', Valid_Token.as_view()),
    re_path('callback', CallBack.as_view()),
    re_path('user_info', Get_user_info.as_view()),
    re_path('up_user', Update_user_info.as_view()),
    re_path('del_user', Delete_user.as_view()),
    # re_path('get42token', Get42Tok.as_view()),
]