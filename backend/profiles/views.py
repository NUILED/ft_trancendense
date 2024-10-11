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
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.tokens import RefreshToken
import pyotp
#import redirect from django.shortcuts
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
                    'email': user.email,
                    'first_name':user.first_name,
                    'access': str(token.access_token),
                    'refresh': str(token),
                })
        except Exception as e:
            return Response({'error': str(e)}, status=500)

class Sign_upView(APIView):
    permission_classes = [AllowAny]  # Allow anyone, even unauthenticated users
    def post(self,request):
        try:
            serialaizer = User_Register(data=request.data)
            if serialaizer.is_valid(raise_exception=True):
                user = serialaizer.save()
                self.send_confirmation_email(user)
                return Response(
                    {'detail': 'Registration successful. Please confirm your email.'},
                    status=status.HTTP_201_CREATED
                )
        except Exception as e:
            if 'email' in str(e):
                return Response(
                    {'detail': 'email already exists.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            elif 'passwords' in str(e):
                return Response(
                    {'detail': 'Passwords do not matches.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            else:
                return Response(
                    {'detail': str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )

    def send_confirmation_email(self,user):
        try:
            id = user.id          
            payload = {'id': id}
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            activation_link = f"http://localhost:8000/api/activate/?token={token}"
            mail_subject = "Account Activation"
            message = f"Please click the following link to activate your account: {activation_link}"
            send_mail(mail_subject, message , 'admin@admin.com', [user.email])
        except Exception as e:
            pass    

class CallBack(APIView):
    def get(self,request):
        try:
            code = request.GET.get('code')
            token = self.get_access_token(code)
            info = self.user_info(token)
            email = info['email']
            if email:
                user = User_profile.objects.filter(email=email).first()
                if user:
                    token = user.token()
                    return Response ({
                        'email': user.email,
                        'first_name':user.first_name,
                        'access': str(token.access_token),
                        'refresh': str(token),
                    })
            if not user:
                user = {
                    'email': info['email'],
                    'password': info['login'],
                    'first_name': info['first_name'],
                    'last_name': info['last_name'] ,
                    'avatar': info['image']['versions']['large']
                    }
                serialaizer = UserSerializer(data=user)
                serialaizer.is_valid(raise_exception=False)
                serialaizer.save()
                user = User_profile.objects.filter(email=email).first()
                user.is_active = True
                user.save()
            if user:
                token = user.token()
                return {
                    'email': user.email,
                    'first_name':user.first_name,
                    'access': str(token.access_token),
                    'refresh': str(token),
                }
        except :
            return Response({'messege':"invalid code"})

    def get_access_token(self,code):
        api_url = settings.API_URL
        settings.DATA['code'] = code
        data = settings.DATA
        response = requests.post(api_url, data=data)
        return response.json()['access_token']
    
    def user_info(self,token):
        api_url = settings.API_URL_INFO
        DATA_HEADER = {
            'Authorization': 'Bearer ' + token
        }
        data = DATA_HEADER
        response = requests.get(api_url, headers=data)
        return response.json()

class Update_user_info(APIView):
    def put(self,request):
        try:
            infos = request.data
            email = infos['email']
            password = infos['password']
            user = User_profile.objects.filter(email=email).first()
            if not user.check_password(raw_password=password):
                raise AuthenticationFailed('invalid credential')
            elif user:
                user.email = infos['email']
                user.first_name = infos['first_name']
                user.last_name = infos['last_name']
                user.avatar = infos['avatar']
                user.bio = infos['bio']
                user.save()
                return Response({"success"})
            else:
                return Response({"user dose not exsiste"})
        except Exception as e:
            return Response({'error': str(e)}, status=500)

class Get_user_info(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request):
        try:
            email = request.data['email']
            user = User_profile.objects.filter(email=email).first()
            if user:
                serialaizer = UserSerializer(user)
                return Response({'info':serialaizer.data})
            else:
                return Response({'info':'user not found'})
        except:
            return Response({'info':'user not found'})

class Delete_user(APIView):
    def delete(self,request):
        try:
            email = request.data['email']
            user = User_profile.objects.filter(email=email).first()
            if user:
                user.delete()
                return Response({'info':'Deleted'})
            else:
                return Response({'info':'user not found'})
        except:
            return Response({'info':'user not found'})

    def post(self,request):
        try:
            resetserializer = RestSerializer(data=request.data)
            if resetserializer.is_valid(raise_exception=True):
                return Response({"detail": "email has been send to reset password"}, status=status.HTTP_200_OK)
            return Response({"detail": "Authorization header missing or invalid."}, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response({"detail": "Authorization header missing or invalid."}, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    # here we just get the refresh token directly from the header
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            token = request.data['refresh']
            refresh_token = RefreshToken(token)
            refresh_token.blacklist()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        except (TokenError, InvalidToken):
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

    #django set password view

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
    def post(self,request):
        try:
            email = request.data['email']
            user = User_profile.objects.get(email=email)
            if user and user.is2fa:
                totp = pyotp.TOTP(user.pyotp_secret)
                if totp.verify(request.data['otp']):
                    token = user.token()
                    return Response({
                        'email': user.email,
                        'first_name':user.first_name,
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
                url = f'https://accounts.google.com/o/oauth2/auth?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope=email'
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
            platform = platform.strip().lower()
            if not platform or not code:
                raise AuthenticationFailed('platform and code are required')
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
                        'redirect_uri': settings.API_URL
                    }
            response = requests.post(url, data=data, headers=headers, timeout=10000)
            if response.status_code != 200:
                raise AuthenticationFailed('invalid access token')
            print(response.json())
            return Response({'info':'successfull'}, status=200)       
            # serializer = self.serializer_class()
            # email = serializer.is_valid(raise_exception=True)
            # print(email)
            return Response({'info':'success'}, status=200)
        except requests.exceptions.RequestException as e:
            return Response({'info':str(e)}, status=400)
            