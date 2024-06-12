from django.db import models
from django.contrib.auth.models import AbstractUser,Group, Permission


class User_profile(AbstractUser):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField(max_length=255,unique=True)
    avatar = models.CharField(max_length=255, default='img url')
    bio = models.CharField(max_length=300,default="write somthing nice here")
    password = models.CharField(max_length=255)
    is_valid = models.BooleanField(default=False)

    username = None 

    REQUIRED_FIELDS = ['email','password']
    groups = models.ManyToManyField(Group, related_name='user_profiles')
    user_permissions = models.ManyToManyField(Permission, related_name='user_profiles')

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