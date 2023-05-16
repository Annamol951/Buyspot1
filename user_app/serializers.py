from datetime import datetime, timedelta
import random
from django.conf import settings
from rest_framework import serializers
from user_app.utils import send_otp
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from .models import UserModel



class UserSerializer(serializers.ModelSerializer):
    """
    User Serializer.

    Used in POST and GET
    """

    password1 = serializers.CharField(
        write_only=True,
        min_length=settings.MIN_PASSWORD_LENGTH,
        error_messages={
            "min_length": "Password must be longer than {} characters".format(
                settings.MIN_PASSWORD_LENGTH
            )
        },
    )
    password2 = serializers.CharField(
        write_only=True,
        min_length=settings.MIN_PASSWORD_LENGTH,
        error_messages={
            "min_length": "Password must be longer than {} characters".format(
                settings.MIN_PASSWORD_LENGTH
            )
        },
    )

    class Meta:
        model = UserModel
        fields = [
            "id",
            "phone_number",
            "email",
            "password1",
            "password2",
        ]
        read_only_fields = ("id",)

    def validate(self, data):
        """
        Validates if both password are same or not.
        """

        if data["password1"] != data["password2"]:
            raise serializers.ValidationError("Passwords do not match")
        return data
    

    def create(self, validated_data):
        """
        Create method.

        Used to create the user
        """
        otp = random.randint(1000, 9999)
        otp_expiry = datetime.now() + timedelta(minutes = 10)

        user = UserModel(
            phone_number=validated_data["phone_number"],
            email=validated_data["email"],
            otp=otp,
            otp_expiry=otp_expiry,
            max_otp_try=settings.MAX_OTP_TRY
        )
        user.set_password(validated_data["password1"])
        user.save()
        # sending otp
        send_otp(validated_data["phone_number"], otp)
        return user



#login

from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = ('id', 'phone_number', 'email', 'password') 

class TokenPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['phone_number'] = user.phone_number
        return token

class UserEditSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = ('id', 'email','address')




class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    phone_number = serializers.CharField(required=False)
    def validate_email(self, email):
        try:
            validate_email(email)
            return email
        except ValidationError:
            raise serializers.ValidationError('Invalid email address')

class NewPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(min_length=8)

    def validate_new_password(self, new_password):
        # validate password strength
        if len(new_password) < 8:
            raise serializers.ValidationError('New password must be at least 8 characters long')
        return new_password

class LoginSerializer(serializers.Serializer):
    phone_number = serializers.CharField()
    password = serializers.CharField() 
    def validate(self, data):
        phone_number = data.get('phone_number')
        password = data.get('password') 

        user = authenticate(phone_number=phone_number, password1=password)
        if not user:
            raise serializers.ValidationError('Invalid username or password')

        return data