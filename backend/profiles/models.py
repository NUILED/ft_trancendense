from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken
from .manager import UserManager

class User_profile(AbstractBaseUser,PermissionsMixin):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField(max_length=255,unique=True)
    password = models.CharField(max_length=255)
    avatar = models.CharField(max_length=255, default='img url')
    bio = models.CharField(max_length=300,default="write somthing nice here")
    is_valid = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name','last_name']

    objects = UserManager()

    def token(self):
        refresh = RefreshToken.for_user(self)
        return refresh
    
    def __str__(self):
        return f'{self.first_name} {self.last_name} ({self.email})'
    
    