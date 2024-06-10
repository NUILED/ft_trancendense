from rest_framework import serializers 
from .models import User_profile

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
    