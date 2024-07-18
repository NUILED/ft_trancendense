from rest_framework import serializers 
from .models import User_profile
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed

class User_Register(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68,min_length=6,write_only=True)
    password1 = serializers.CharField(max_length=68,min_length=6,write_only=True)

    class Meta:
        model = User_profile
        fields = ['email','password','password1','first_name','last_name','bio']

    def valideate(self,attrs):
        return super().validate(attrs)


    def create(self,attrs):
        return super().validate(attrs)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User_profile
        fields = ['id','email','password','first_name','last_name','avatar','bio']
        extra_kwargs = {
            'password':{'write_only':True}
        }

    def create(self,validated_data):
        password = validated_data.pop('password',None)
        instance = self.Meta.model(**validated_data)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class LoginUserSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(max_length=255)
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=255,write_only=True)
    access = serializers.CharField(max_length=255,read_only=True)
    refresh = serializers.CharField(max_length=255,read_only=True)
    class Meta:
        model = User_profile
        fields = ['email','password','first_name','access','refresh']

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        try:
            user = User_profile.objects.get(email=email)
        except:
            raise AuthenticationFailed("invalid credentials try again")
        if not user.is_active:
            raise AuthenticationFailed('User not Found or password incorrect')
        if not user.check_password(raw_password=password):
            raise AuthenticationFailed('User not Found or password incorrect')
        token = user.token()
        return {
            'email': user.email,
            'first_name':user.first_name,
            'access': str(token.access_token),
            'refresh': str(token),
        }



class ResetPassword(serializers.ModelSerializer):
    pass
             