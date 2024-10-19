from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .serializer import UserSerializer , LoginUserSerializer ,User_Register , SocialAuthontication
from .models import User_profile
import jwt 
from django.core.serializers import deserialize
from django.conf import settings
import requests
import json
from django.core.mail import send_mail 
from rest_framework.permissions import IsAuthenticated ,AllowAny
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
import pyotp
from django.shortcuts import redirect

class LoginView(APIView):
    permission_classes = [AllowAny]  # Allow anyone, even unauthenticated users
    serializer_class = LoginUserSerializer
    def post(self, request):
        data = self.serializer_class(data=request.data)
        try:
            if data.is_valid(raise_exception=True):
                user = data.validated_data
                if user.is2fa:
                    return Response({'info':'2fa enabled'})
                token = user.token()
                return Response({
                    'access': str(token.access_token),
                    'refresh': str(token),
                },status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class Sign_upView(APIView):
    permission_classes = [AllowAny]  # Allow anyone, even unauthenticated users
    def post(self,request):
        try:
            email = request.data.get('email', None)
            username = request.data.get('username', None)
            print('dara->',request.data)
            if User_profile.objects.filter(email=email).exists():
                raise AuthenticationFailed('Email already exists')
            if User_profile.objects.filter(username=username).exists():
                raise AuthenticationFailed('Username already exists')
            serialaizer = User_Register(data=request.data)
            if serialaizer.is_valid(raise_exception=True):
                user = serialaizer.save()
                return Response(
                    {'detail': 'Registration successful.'},
                    status=status.HTTP_201_CREATED
                )
        except Exception as e:
                return Response(
                    {str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )

class Update_user_info(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    def put(self, request):
        try:
            infos = request.data
            user = request.user
            if infos["email"] and infos["email"] != user.email:
                if User_profile.objects.filter(email=infos["email"]).exists():
                    raise AuthenticationFailed('Email already exists')
            if infos["username"] and infos["username"] != user.username:
                if User_profile.objects.filter(username=infos["username"]).exists():
                    raise AuthenticationFailed('Username already exists')
            serializer = self.serializer_class().update(user, infos)
            serializer.save()
            return Response({"message": "User updated successfully!"},status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class Get_user_info(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    def get(self,request):
        try:
            user = request.user
            serialized_user = self.serializer_class(user)
            return Response(serialized_user.data)
        except Exception as e:
            return Response({'info':str(e)},status=400)

class LogoutView(APIView):
    # here we just get the refresh token directly from the header
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            token = request.data['refresh']
            refresh_token = RefreshToken(token)
            refresh_token.blacklist()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        except TokenError:
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

class Control2Fa(APIView):
    permission_classes = [IsAuthenticated]
    def post(self,request):
        try:
            email = request.data['email']
            user = User_profile.objects.get(email=email)
            if user:
                user.pyotp_secret = pyotp.random_base32()
                otp = pyotp.TOTP(user.pyotp_secret).provisioning_uri(user.email, issuer_name="2fa")
                user.is2fa = True
                user.save()
                return Response({'otp':otp,'info':'2fa enabled'},status=200)
            else:
                return Response({'info':'user not found'},status=400)
        except:
            return Response({'info':'user not found'},status=400)
    
    def get(self,request):
        try:
            email = request.data['email']
            user = User_profile.objects.get(email=email)
            if user:
                user.is2fa = False
                user.save()
                return Response({'info':'2fa disabled'},status=200)
            else:
                return Response({'info':'user not found'},status=400)
        except:
            return Response({'info':'user not found'},status=400)
        
class Signin2fa(APIView):
    permission_classes = [AllowAny]
    def post(self,request):
        try:
            email = request.data['email']
            user = User_profile.objects.get(email=email)
            if user and user.is2fa:
                totp = pyotp.TOTP(user.pyotp_secret)
                if totp.verify(request.data['otp']):
                    token = user.token()
                    return Response({
                        'access': str(token.access_token),
                        'refresh': str(token),
                    },status=200)
                else:
                    return Response({'info':'invalid otp'},status=400)
            else:
                return Response({'info':'user not found or 2fa not enabled'},status=400)
        except:
            return Response({'info':'user not found'},status=400)

class SocialAuth(APIView):
    permission_classes = [AllowAny]
    def post(self,request):
        try:
            platform = request.data['platform']
            if platform == 'github':
                client_id = settings.GITHUB_CLIENT_ID
                redirect_uri = settings.GITHUB_REDIRECT_URI
                url = f'https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=user:email'
            elif platform == 'gmail':
                client_id = settings.G_CLIENT_ID
                redirect_uri = settings.G_REDIRECT_URI
                url = f'https://accounts.google.com/o/oauth2/auth?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope=openid email profile'
            elif platform == "42":
                client_id = settings.CLIENT_ID
                redirect_uri = settings.INTRA_REDIRECT_URI
                url = f'https://api.intra.42.fr/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code'
            return redirect(url)
        except requests.exceptions.RequestException as e:
            return Response({'info':'error'},status=400)

class SocialAuthverify(APIView):
    permission_classes = [AllowAny]
    serializer_class = SocialAuthontication
    def get(self, request):
        try:
            headers = {'Accept': 'application/json'}
            platform = request.GET.get('platform')
            code = request.GET.get('code')
            if not platform and not code:
                raise AuthenticationFailed('platform and code are required')
            if platform:
                platform = platform.strip().lower()
                if platform == 'github':
                    url = 'https://github.com/login/oauth/access_token'
                    data = {
                    'client_id': settings.GITHUB_CLIENT_ID,
                    'client_secret': settings.GITHUB_CLIENT_SECRET,
                    'code': code,
                    'redirect_uri': settings.GITHUB_REDIRECT_URI
                    }
                elif platform == 'gmail':
                    url = 'https://oauth2.googleapis.com/token'
                    data = {
                        'client_id': settings.G_CLIENT_ID,
                        'client_secret': settings.G_CLIENT_SECRET,
                        'code': code,
                        'redirect_uri': settings.G_REDIRECT_URI,
                        'grant_type': 'authorization_code'
                    }
            else:
                url = 'https://api.intra.42.fr/oauth/token'
                data = {    
                        'grant_type': 'authorization_code',
                        'client_id': settings.CLIENT_ID,
                        'client_secret': settings.CLIENT_SECRET,
                        'code': code,
                        'redirect_uri': settings.INTRA_REDIRECT_URI
                    }
                platform = '42'
            response = requests.post(url, data=data, headers=headers, timeout=10000)
            response.raise_for_status()
            access_token = response.json()['access_token']
            data = {
                'access_token': access_token,
                'platform': platform
            }
            serializer = self.serializer_class(data=data)
            if serializer.is_valid(raise_exception=True):
                email = serializer.validated_data
                user  = User_profile.objects.filter(email=email).first()
                if user :
                    token = user.token()
                    return Response({
                        'access': str(token.access_token),
                        'refresh': str(token),
                    })
                else:
                    return Response({'info':'user not found'},status=400)
        except requests.exceptions.RequestException as e:
            return Response({'info':str(e)}, status=400)
