from django.urls import path
from . import views

from .views import *


urlpatterns = [
    path('register/', views.RegisterView.as_view()),
    path('verify_otp/<int:pk>', views.VerifyOTP.as_view()),
    path('regenerate_otp/<int:pk>', views.RegenerateOTP.as_view()),
    path('update_user/<int:pk>', views.UpdateUser.as_view()),
    path('forgot_password', views.ForgotPasswordView.as_view()),
    path('update_password/<int:pk>', UpdatePasswordView.as_view()),

    #path('LoginAPIView/', views.LoginAPIView.as_view()),
    path('login', LoginView.as_view()),

    
]