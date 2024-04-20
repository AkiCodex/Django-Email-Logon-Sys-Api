from rest_framework import serializers
from .models import User
from xml.dom import ValidationErr
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util
from django.contrib.auth import get_user_model


class UserRegistrationSerializer(serializers.ModelSerializer):
    
    password2 = serializers.CharField(style={'input_type': 'password'})
    
    
    class Meta:
        model = User
        fields= ['email', 'name', 'tc', 'password' ,'password2']
        extra_kwargs = {
            'password' : {'write_only':True},
            'password2' : {'write_only':True},  
        }
        
        
    def validate(self,attrs):#validation
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=250)
    class Meta:
        model = User
        fields= ['email','password']


        
class UserProfileSerializer(serializers.ModelSerializer):
     class Meta:
        model = User
        fields= ['id','email', 'name', 'tc', 'password' ,'password2']
  
        
class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    
    def validate_password(self, value):
        password = value
        password2 = self.initial_data.get('password2')
        
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password don't match")
        
        return value
    
    def save(self, **kwargs):
        user = self.context['user']
        user.set_password(self.validated_data['password'])
        user.save()
        


UserModel = get_user_model()

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=250)
    
    def validate_email(self, value):
        try:
            user = UserModel.objects.get(email=value)
        except UserModel.DoesNotExist:
            raise serializers.ValidationError("Email does not exist")

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetTokenGenerator().make_token(user)
        link = f'http://127.0.0.1:8000/api/user/reset-password/{uid}/{token}'
        # Send email here
        data = {
            subject : 'Password Reset',
            body : 'Click the link below to reset your password',
            message : link,
            to : [user.email]
        }
        Util.send_email(data)
        
        print('Password Reset Link:', link)
        return value


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password don't match")
        
        uid = self.context.get('uid')
        token = self.context.get('token')

        try:
            user_id = smart_str(urlsafe_base64_decode(uid))
            user = UserModel.objects.get(pk=user_id)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist, DjangoValidationError):
            raise serializers.ValidationError('Invalid user ID')

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError('Token is not valid or expired')

        user.set_password(password)
        user.save()
        return attrs
            
    
   
                
        