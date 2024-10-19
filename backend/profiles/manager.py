from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError

class UserManager(BaseUserManager):
    def create_user(self,email,password=None,**extra_fields):
        email = self.normalize_email(email)
        user = self.model(email=email,**extra_fields)
        user.set_password(password)
        user.save(self._db)
        return user
    
    def create_superuser(self,email,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser',True)
        if not extra_fields.get('is_staff'):
            raise ValueError('is_staff is required')
        if not extra_fields.get('is_superuser'):
            raise ValueError('is_superuser is required')
        user = self.create_user(
            email,password,**extra_fields
        )
        return user
