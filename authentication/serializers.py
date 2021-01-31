from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth import password_validation
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from django.contrib.auth.hashers import check_password

class RegisterSerializer(serializers.ModelSerializer):
    password=serializers.CharField(max_length=68, min_length=6, write_only=True)
    
    class Meta:
        model=User
        fields =  ['email','username','password', 'firstname', 'lastname']
        
    def validate(self, attrs):
        email = attrs.get('email','')
        username = attrs.get('username','')
        password = attrs.get('password','')
        firstname = attrs.get('firstname','')
        lastname = attrs.get('lastname','')
        if not username.isalnum():
           
            raise serializers.ValidationError(
                'The username should only contain alphanumeric characters') 
        return attrs
       
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
        
        
class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']
model = User
class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(
        max_length=255, min_length=3, read_only=True)
    firstname = serializers.CharField(max_length=255, min_length=3, read_only=True)
    lastname = serializers.CharField(max_length=255, min_length=3, read_only=True)
    tokens = serializers.CharField(max_length=68, min_length=6, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens','firstname','lastname']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)
        
        if not user:
            raise AuthenticationFailed('Invalid credentials, Try again')

        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')

        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')


        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens
        }

        return super().validate(attrs)    
        
class ListUsers(serializers.ModelSerializer):
    class Meta:
      model = User
      fields = ['email', 'username', 'is_verified','is_active','tokens','firstname','lastname','password']




class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=68,min_length=2)
    password = serializers.CharField(max_length=68,  write_only=True)
    class Meta:
        model = User
        fields = ['email','password']

    def validate(self, attrs):
        email = attrs.get('email','')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email,password=password)
        
        if not user:
            raise AuthenticationFailed('Invalid credentials, Try again')

        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')

        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')
        return super().validate(attrs) 
        
        


class SetNewPasswordSerializer(serializers.Serializer):
     new_password=serializers.CharField(
         min_length=6, max_length=68, write_only=True)
     token=serializers.CharField(
         min_length=1, write_only=True)
     uidb64=serializers.CharField(
         min_length=1, write_only=True)

     class Meta:
         model = User
         fields = ['email','password','new_password','token', 'uidb64']
     
    

     def validate(self, attrs):
         try:
             new_password = attrs.get('new_password')
             token = attrs.get('token')
             uidb64 = attrs.get('uidb64')

             id = force_str(urlsafe_base64_decode(uidb64))
             user = User.objects.get(id=id)
           
            

             if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

             

             user.set_password(new_password)
             user.save()

             return (user)
         except Exception as e:  
            raise AuthenticationFailed('The reset link is invalid', 401)
         return super().validate(attrs)


