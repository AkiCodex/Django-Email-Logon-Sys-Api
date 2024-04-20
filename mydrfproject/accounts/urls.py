from django.contrib import admin
from django.urls import path, include
from .views import UserRegistrationView,UserPasswordResetView,UserLoginView,UserPofileView,UserChangePasswordView,SendResetEmailView

app_name = 'home'

urlpatterns = [
   
    path("user/register/", UserRegistrationView.as_view(), name='register'),
    path("user/login/", UserLoginView.as_view(), name='login'),
    path("user/profile/", UserPofileView.as_view(), name='profile'),
    path("user/chagepassword/", UserChangePasswordView.as_view(), name='chagepassword'),
    path("user/send-reset-email/", SendResetEmailView.as_view(), name='send-reset-email'),
    path("user/reset-password/<uid>/<token>/", UserPasswordResetView.as_view()),
    # path("", include('django.contrib.auth.urls')),
    
]