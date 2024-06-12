from django.contrib import admin
from django.urls import re_path , include

urlpatterns = [
    re_path('api/', include('profiles.urls')),
    re_path('admin/', admin.site.urls),  # This includes the Django admin URLs
    # re_path('callback', views.callback , name="callback"),
    # re_path('login', views.login , name="login"),
    # re_path('sign_up', views.sign_up , name="sign_up"),
    # re_path('token', views.get_token , name="token"),
]
