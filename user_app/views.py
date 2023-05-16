# Create your views here.

#check

#import datetime
import random
import requests
from django.conf import settings
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.mail import send_mail
import pyotp

from user_app.utils import send_otp

from .models import UserModel
from .serializers import LoginSerializer,UserSerializer, TokenPairSerializer,UserEditSerializer,ForgotPasswordSerializer,NewPasswordSerializer
from django.core.mail import EmailMessage
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, HttpResponseRedirect, Http404, get_object_or_404
from django.contrib.auth import logout, login, authenticate

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
#from django.conf import get_or_create
#from django.shortcuts import get_or_create
#from django.contrib.auth import get_or_create
import jwt
from datetime import datetime, timedelta
from django.conf import settings

now = timezone.now()

def generate_jwt_token(user):
    # generate JWT token with user id as payload
    payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(days=7),
        'iat': datetime.utcnow()
    }

    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token


class RegisterView(APIView):
    def get(self, request):
        data=UserModel.objects.all()
        print(data)
        serializer = UserSerializer(data, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors)
    
    


class VerifyOTP(APIView):
    """
    UserModel View.
    """

    #queryset = UserModel.objects.all()
    #erializer_class = UserSerializer

    #@action(detail=True, methods=["PATCH"])
#varify_otp

    def put(self, request, pk=None):
        queryset = UserModel.objects.get(id=pk)
        #instance = self.get_object()
        if (
            not queryset.is_active
            and queryset.otp == request.data.get("otp")
            and queryset.otp_expiry
            and timezone.now() < queryset.otp_expiry
        ):
            queryset.is_active = True
            queryset.otp_expiry = None
            queryset.max_otp_try = settings.MAX_OTP_TRY
            queryset.otp_max_out = None
            queryset.save()
            return Response(
                "Successfully verified the user.", status=status.HTTP_200_OK
            )

        return Response(
            "User active or Please enter the correct OTP.",
            status=status.HTTP_400_BAD_REQUEST,
        )

class RegenerateOTP(APIView):
    def put(self, request, pk=None):
        """
        Regenerate OTP for the given user and send it to the user.
        """
        instance = UserModel.objects.get(id=pk)
        if int(instance.max_otp_try) == 0 and timezone.now() < instance.otp_max_out:
            return Response(
                "Max OTP try reached, try after an hour",
                status=status.HTTP_400_BAD_REQUEST,
            )

        otp = random.randint(1000, 9999)
        #otp_expiry = timezone.now() + datetime.timedelta(minutes=10) #to check
        otp_expiry = timezone.now() + timedelta(minutes=10)
        max_otp_try = int(instance.max_otp_try) - 1
        print(instance.otp)
        instance.otp = otp
        instance.otp_expiry = otp_expiry
        instance.max_otp_try = max_otp_try
        if max_otp_try == 0:
            # Set cool down time
            #otp_max_out = timezone.now() + datetime.timedelta(hours=1) #to check
            otp_max_out = timezone.now() + timedelta(hours=1)
            instance.otp_max_out = otp_max_out
        elif max_otp_try == -1:
            instance.max_otp_try = settings.MAX_OTP_TRY
        else:
            instance.otp_max_out = None
            instance.max_otp_try = max_otp_try
        instance.save()
        send_otp(instance.phone_number, otp)
        send_otp(instance.email, otp)
        return Response("Successfully generate new OTP.", status=status.HTTP_200_OK)
    



class UpdateUser(APIView):
    def get(self,request,pk):
        user = UserModel.objects.get(id=pk)
        serializer = UserEditSerializer(user)
        return Response(serializer.data)
    def put(self,request,pk):
        user = UserModel.objects.get(id=pk)
        user.first_name = request.data.get('first_name', user.first_name)
        user.last_name = request.data.get('last_name', user.last_name)
        user.email = request.data.get('email', user.email)
        user.address = request.data.get('address', user.address)
        user.save()
        return Response({'message': 'User updated successfully.'})

class ForgotPasswordView(APIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        user = UserModel.objects.filter(email=email).first()

        if user:
            # generate and save a password reset token
            token = PasswordResetTokenGenerator().make_token(user)
            otp = random.randint(1000, 9999)
            otp_expiry = timezone.now() + datetime.timedelta(minutes=10)
            user.otp = otp
            user.otp_expiry = otp_expiry
            user.password_reset_token = token
            user.save()
            send_otp(user.phone_number, otp)
            # send an email with the password reset link
            subject = 'Password reset request'
            message = str(otp)
            # message = f'Please use the following link to reset your password: {request.build_absolute_uri(f"/reset-password/{urlsafe_base64_encode(force_bytes(user.pk)).decode()}?token={token}")}'
            email_from = 'manojantony.bsdt@gmail.com'
            recipient_list = [email]
            email_message = EmailMessage(subject, message, email_from, recipient_list)
            email_message.send()

        # always return a successful response to prevent email address enumeration attacks
        return Response({'status': 'success'})

class UpdatePasswordView(APIView):
    serializer_class = NewPasswordSerializer

    def put(self, request,pk):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = UserModel.objects.get(id=pk)
        user.set_password(serializer.validated_data['new_password'])
        user.save()

        return Response({'status': 'success'}, status=status.HTTP_200_OK)
class LoginView(APIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(phone_number=serializer.validated_data['phone_number'],
                            password=serializer.validated_data['password'])

        if not user:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        # login the user
        login(request, user)

        # generate JWT token and return in response
        token = generate_jwt_token(user)
        return Response({'token': token}, status=status.HTTP_200_OK)