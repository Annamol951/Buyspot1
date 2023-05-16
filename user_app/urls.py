from django.urls import path
from . import views

from .views import *

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [

    path('register/', views.RegisterView.as_view()),                 # for register the user
    path('verify_otp/<int:pk>', views.UserView.as_view()),           #for verify the user
    path('regenerate_otp/<int:pk>', views.RegenerateOTP.as_view()),  #for regenerate the OTP
    path('login/', LoginView.as_view()),                             # for login
    path('logout/', LogoutView.as_view()),                           # for logout
    path('forgot_password', views.ForgotPasswordView.as_view()),     #forgot password
    path('update_password/<int:pk>', UpdatePasswordView.as_view()),  #update password


    path('delivery_address/', DeliveryAddressAPIView.as_view()), #for create and update
    path('delivery_address/<int:id>/', DeliveryAddressDetailAPIView.as_view()),  #for view


    path('token/', TokenObtainPairView.as_view()),                   #name='token_obtain_pair'
    path('token/refresh/', TokenRefreshView.as_view()),              #name='token_refresh'

    # path('register/', views.RegisterView.as_view()),
    # path('verify_otp/<int:pk>', views.verifyOTP.as_view()),
    # path('regenerate_otp/<int:pk>', views.RegenerateOTP.as_view()),
    #path('update_user/<int:pk>', views.UpdateUser.as_view()),
    #path('forgot_password', views.ForgotPasswordView.as_view()),
    #path('update_password/<int:pk>', UpdatePasswordView.as_view()),

    #path('LoginAPIView/', views.LoginAPIView.as_view()),
    #path('login', LoginView.as_view()),

    
]