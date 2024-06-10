from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .serializer import UserSerializer
from .models import User_profile
import jwt 
from django.core.serializers import deserialize
from django.conf import settings
import requests
import json

class Sign_upView(APIView):
    def post(self,request):
        serialaizer = UserSerializer(data=request.data)
        serialaizer.is_valid(raise_exception=True)
        serialaizer.save()
        return Response(serialaizer.data)

class LoginView(APIView):
    def post(self,request):
        try:
            email = request.data['email']
            password = request.data['password']
        except:
            raise AuthenticationFailed('User not Found or password incorrect')
        user = User_profile.objects.filter(email=email).first()
        if user is None:
            raise AuthenticationFailed('User not Found or password incorrect')
        if not user.check_password(raw_password=password):
            raise AuthenticationFailed('User not Found or password incorrect')
        payload = {
            'id' : user.email
        }
        token = jwt.encode(payload,settings.SECRET_KEY,algorithm='HS256')
        res = Response()
        res.set_cookie(key='access_token', value=token, httponly=True)
        res.data = {
            'access_token': token
        }
        return res

class GetToken(APIView):
    def get(self,request):
        try:
            token = request.COOKIES.get('access_token')
            payload = jwt.decode(token,settings.SECRET_KEY,algorithms='HS256')
        except:
            raise AuthenticationFailed('Token is not Valid')
        user = User_profile.objects.filter(email=payload['email']).first()
        if not user:
            raise AuthenticationFailed('Token is not Valid')
        serialaizer = UserSerializer(user)
        res = Response()
        res.set_cookie(key='access_token', value=token, httponly=True)
        res.data = {
            'messege': serialaizer.data
        }
        return res

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
                payload = {'id' : serialaizer.data['email']}
            else:
                payload = {'id' : user.email}
            r_token = jwt.encode(payload,settings.SECRET_KEY,algorithm='HS256')
            res = Response()
            res.set_cookie(key='access_token', value=r_token, httponly=True)
            res.data = {
            'access_token': r_token
            }
            return res
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

class Get_user_info(APIView):
    def get():
        pass

class Get_user_info(APIView):
    def get():
        pass
