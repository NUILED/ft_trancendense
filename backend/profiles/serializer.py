from rest_framework import serializers 
from .models import User_profile
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.exceptions import AuthenticationFailed
import requests

class User_Register(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=55, min_length=8, allow_blank=False)
    password = serializers.CharField(max_length=68,min_length=6,write_only=True)

    class Meta:
        model = User_profile
        fields = ['email','first_name','last_name','username' ,'password']

    def create(self, validated_data):
        password = validated_data.pop('password',None)
        user = User_profile.objects.create_user(**validated_data)
        user.set_password(password)
        if not user.username:
            user.username = user.email.split('@')[0]
        user.save()
        return user

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

class LoginUserSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=55, min_length=8, allow_blank=False)
    password = serializers.CharField(max_length=16,min_length=8,write_only=True,required=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        try:
            user = User_profile.objects.get(email=email)
        except:
            raise AuthenticationFailed("invalid credentials try again")
        
        if not user.check_password(raw_password=password):
            raise AuthenticationFailed('User not Found or password incorrect')
        
        return user

class SocialAuthontication(serializers.Serializer):
    def validate(self, data):
        data = self.initial_data
        access_token = data['access_token']
        platform = data['platform']
        headers = {'Authorization':f'Bearer {access_token}'}
        if platform == "github":
            response = requests.get('https://api.github.com/user/emails',headers=headers, timeout=10000)
            response.raise_for_status()
            res = response.json()
            email = None
            for fileds in res:
                if fileds['primary'] == True:
                    email = fileds['email']
                    break
            if email is None:
                raise serializers.ValidationError('email is required')
            user , created = User_profile.objects.get_or_create(email=email)
            if user is not None:
                return user.email
            elif created: 
                userinfo = requests.get('https://api.github.com/user',headers=headers, timeout=10000)
                userinfo.raise_for_status()
                created.user.username = userinfo.json()['login']
                created.user.first_name = userinfo.json()['name'].split(' ')[0]
                created.user.last_name = userinfo.json()['name'].split(' ')[1]
                created.user.avatar = userinfo.json()['avatar_url']
                created.user.save()
                return created.user.email
        elif platform == "gmail":
            response = requests.get('https://www.googleapis.com/oauth2/v1/userinfo',headers=headers, timeout=10000)
            response.raise_for_status()
            res = response.json()
            email = res['email']
            if email is None:
                raise serializers.ValidationError('email is required')
        elif platform == "42":
            response = requests.get('https://api.intra.42.fr/v2/me',headers=headers, timeout=10000)
            response.raise_for_status()
            res = response.json()
            email = res['email']
        if email is None:
            raise serializers.ValidationError('email is required')
        return res

