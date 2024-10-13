from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken
from .manager import UserManager

class User_profile(AbstractBaseUser,PermissionsMixin):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    username = models.CharField(max_length=20, unique=True, null=True, blank=True)
    email = models.EmailField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    avatar = models.CharField(max_length=255, default='img url')
    bio = models.CharField(max_length=300, default="write somthing nice here")
    is_valid = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=True)
    pyotp_secret = models.CharField(max_length=255, default='')
    
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=False, null=True)
    last_login = models.DateTimeField(auto_now=True, null=True)
    is2fa = models.BooleanField(default=False)
    wins = models.IntegerField(default=0)
    losses = models.IntegerField(default=0)
    draws = models.IntegerField(default=0)
    matches_played = models.IntegerField(default=0)

    USERNAME_FIELD = 'email'
    objects = UserManager()

    def token(self):
        refresh = RefreshToken.for_user(self)
        return refresh
    
    def __str__(self):
        return f'{self.first_name} {self.last_name} {self.email}'
    
    