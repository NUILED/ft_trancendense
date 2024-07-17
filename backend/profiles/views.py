from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .serializer import UserSerializer , LoginUserSerializer
from .models import User_profile
import jwt 
from django.core.serializers import deserialize
from django.conf import settings
import requests
import json
from django.core.mail import send_mail


class LoginView(APIView):
    def post(self, request):
        loginserializer = LoginUserSerializer(data=request.data, context={'context': request})
        if loginserializer.is_valid(raise_exception=True):
            return Response(loginserializer.data, status=status.HTTP_200_OK)
        return Response({"detail": "User with this email already exists."}, status=status.HTTP_400_BAD_REQUEST)

class Sign_upView(APIView):
    def post(self,request):
        serialaizer = UserSerializer(data=request.data)
        try:
            if serialaizer.is_valid(raise_exception=True):
                user = serialaizer.save()
                self.send_confirmation_email(user)#fix responce here somthing happend
                return Response(
                    {'detail': 'Registration successful. Please confirm your email.'},
                    status=status.HTTP_201_CREATED
                )
        except Exception as e:
            print(e)
            return Response(
                {"detail": "User with this email already exists."},
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
            send_mail(mail_subject, message, 'info@ft_trancendense.com', [user.email])
        except Exception as e:
            pass

class Activate(APIView):
    def get(self,request):
        token = request.GET.get('token')
        payload = {'id':token}
        id = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        user_id = id['id']
        user = User_profile.objects.filter(id=user_id).first()
        if user.is_valid == True:
            return Response({'detail': 'confirmatration allready done'})
        elif user:
            user.is_valid = True
            user.save()
            return Response({'detail': 'confirmatration successful '})
        return Response({'detail': 'confirmatration unsuccessful'})

class CallBack(APIView):
    def get(self,request):
        try:
            code = request.GET.get('code')
            token = self.get_access_token(code)
        except Exception as e:
            return Response({'messege':"invalid code"})
        try:
            info = self.user_info(token)
            email = info['email']
        except Exception as e:
            return Response({'messege':"too many calls"})
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
        else:
            return Response({"error"})

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

