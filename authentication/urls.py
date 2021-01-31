from django.urls import path
from .views import RegisterView, VerifyEmail, LoginAPIView, PasswordTokenCheckAPI, RequestPasswordResetEmail, SetNewPasswordAPIView,UserListAPIView
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)






urlpatterns = [
    path('register/', RegisterView.as_view(), name="register"),
    path('activate-user/', VerifyEmail.as_view(), name="activate-user"),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('getusers/', UserListAPIView.as_view(), name='Userlist'),
    path('request-reset-password/', RequestPasswordResetEmail.as_view(), name="request-reset-password"),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(), name='password-reset-complete')
]
