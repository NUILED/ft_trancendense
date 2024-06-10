
from django.urls import re_path 
from .views import Sign_upView ,LoginView, GetToken, CallBack 
urlpatterns = [
    re_path('signup', Sign_upView.as_view()),
    re_path('login', LoginView.as_view()),
    re_path('getoken', GetToken.as_view()),
    re_path('callback', CallBack.as_view()),
    # re_path('get42token', Get42Tok.as_view()),
]