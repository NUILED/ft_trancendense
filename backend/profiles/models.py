from django.db import models
from django.contrib.auth.models import AbstractUser,Group, Permission


class User_profile(AbstractUser):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField(max_length=255,unique=True)
    avatar = models.CharField(max_length=255, default='img url')
    bio = models.CharField(max_length=300,default="write somthing nice here")
    password = models.CharField(max_length=255)

    username = None #need to the abstract class

    REQUIRED_FIELDS = ['email','password']
    groups = models.ManyToManyField(Group, related_name='user_profiles')
    user_permissions = models.ManyToManyField(Permission, related_name='user_profiles')




