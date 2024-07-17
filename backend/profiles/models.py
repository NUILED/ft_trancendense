from django.db import models
from django.contrib.auth.models import AbstractBaseUser,Group, Permission
from rest_framework_simplejwt.tokens import RefreshToken


class User_profile(AbstractBaseUser):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField(max_length=255,unique=True)
    avatar = models.CharField(max_length=255, default='img url')
    bio = models.CharField(max_length=300,default="write somthing nice here")
    password = models.CharField(max_length=255)
    is_valid = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['password']
    
    def token(self):
        refresh = RefreshToken.for_user(self)
        return refresh
    
    def __str__(self):
        return f'{self.first_name} {self.last_name} ({self.email})'
    
    def get_profile_by_id(self):
        try:
            return self.id
        except User_profile.DoesNotExist:
            return None
    
    @staticmethod
    def check_by_id(self, id):
        if self.id == id:
            return self
        return False
    