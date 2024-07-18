from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _




class UserManager(BaseUserManager):
    def email_validator(self,email):
        try:
            validate_email(email)
        except ValidationError:
            raise ValueError(_('please validate email'))
    def create_user(self,email,first_name,last_name,password,**extra_fields):
        if email:
            email = self.normalize_email(email)
            self.email_validator(email)
        else:
            raise ValueError(_('email is required'))
        if not first_name:
            raise ValueError(_('first_name is required'))
        if not last_name:
            raise ValueError(_('last_name is required'))
        user = self.model(email=email,first_name=first_name,last_name=last_name,**extra_fields)
        user.set_password(password)
        user.save(self._db)
        return user
    
    def create_superuser(self,email,first_name,last_name,password,**extra_fields):
        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser',True)
        extra_fields.setdefault('is_verified',True)
        if not extra_fields.get('is_staff'):
            raise ValueError(_('is_staff is required'))
        if not extra_fields.get('is_superuser'):
            raise ValueError(_('is_superuser is required'))
        user = self.create_user(
            email,first_name,last_name,password,**extra_fields
        )
        return user
    