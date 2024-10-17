from django.urls import path
from .views import *
from django.urls import path
# from .views import start_oauth_flow, oauth2callback


urlpatterns = [
    path('', Home.as_view(), name='home'),
    path('signup/', UserSignUpAPIView.as_view(), name='signup'),
    path('login/', UserLoginAPIView.as_view(), name='login'),
    path('changepassword/', ChangePasswordView.as_view(), name='change-password'),
    path('send-resetpassword/', SendResetPasswordView.as_view(), name='reset-password-email'),
    path('resetpassword/<uid>/<token>/', UserResetPasswordView.as_view(), name='reset-password'),  
    path('profile/', UserProfileAPIView.as_view(), name='user-profile'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
]