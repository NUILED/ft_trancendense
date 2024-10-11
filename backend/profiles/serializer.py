from rest_framework import serializers 
from .models import User_profile
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.exceptions import AuthenticationFailed

class User_Register(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68,min_length=6,write_only=True)
    password1 = serializers.CharField(max_length=68,min_length=6,write_only=True)

    class Meta:
        model = User_profile
        fields = ['email','first_name','last_name' ,'password','password1']
    def validate(self,attrs):
        password = attrs.get('password','')
        password1 = attrs.pop('password1','')
        if password != password1:
            raise serializers.ValidationError('password dose not match')
        return attrs

    def create(self, validated_data):
        user = User_profile.objects.create_user(**validated_data)
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

class LoginUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=255,write_only=True)
    class Meta:
        model = User_profile
        fields = ['email','password','access','refresh']

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        try:
            user = User_profile.objects.get(email=email) #check password
        except:
            raise AuthenticationFailed("invalid credentials try again")
        
        if not user.check_password(raw_password=password):
            raise AuthenticationFailed('User not Found or password incorrect')
        
        return user

class SocialAuthontication(serializers.Serializer):
    def validate(self,attrs):
        access_token = attrs.get('access_token')
        platform = attrs.get('platform')
        headers = {'Authorization':f'Bearer {access_token}'}
        if access_token is None or platform is None:
            raise AuthenticationFailed('access token is required')
        if platfrom == "github":
            response = requests.get('https://api.github.com/user',headers=headers,timeout=10000)
            if response.status_code != 200:
                raise AuthenticationFailed('invalid access token')
            email = response.json().get('email')
            if email is None:
                raise AuthenticationFailed('email is required')
        return email