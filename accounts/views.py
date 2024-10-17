from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import NotAuthenticated, PermissionDenied
from rest_framework.permissions import IsAuthenticated
from accounts.serializers import UserLoginSerializer , UserSignUpSerializer, UserProfileSerializer,ChangePasswordSerializer,SendResetPasswordSerializer, UserResetPasswordSerializer 
from django.contrib.auth import authenticate
from accounts import create_response_util
from rest_framework.exceptions import ValidationError
from rest_framework import serializers, status

from .models import User


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class Home(APIView):
    def get(self, request):
        content = {'message': 'Hello, World!'}
        return Response(content)
    
    

class UserSignUpAPIView(APIView):
    def post(self, request, format=None):
        serializer = UserSignUpSerializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)  # Validate the input data
            user = serializer.save()  # This will call the create method in the serializer
            token = get_tokens_for_user(user)
            
            return create_response_util.create_response_data(
                message="Success",
                status=status.HTTP_201_CREATED,
                data=({
                    "token": token,
                    },serializer.data),
                errors=None,
            )
        except serializers.ValidationError as e:
            return create_response_util.create_response_data(
                message="Password Do Not Match",
                status=status.HTTP_400_BAD_REQUEST,
                data=None,
                errors=e.detail,  # Provide detailed validation errors
            )
        except Exception as e:
            return create_response_util.create_response_data(
                message="An error occurred",
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                data=None,
                errors=str(e),  # Provide a general error message
            )
        
    
    
class UserLoginAPIView(APIView):
  
    def post(self, request, format=None):
        # breakpoint()
        serializer = UserLoginSerializer(data=request.data)
       
        if serializer.is_valid():
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                if user.is_active and user.is_staff:
                    token = get_tokens_for_user(user)
                    print(token)
                    return create_response_util.create_response_data(
                    message="Success",
                    status=status.HTTP_200_OK,
                    data=({
                        "token": token,
                        },
                        serializer.data),
                    errors=None,
                    )
                else:
                    return create_response_util.create_response_data(
                message="User is not autheticate",
                status=status.HTTP_401_UNAUTHORIZED,
                data=None,
                # errors=e.detail,  # Provide detailed validation errors
            )
                    
            else:
                return create_response_util.create_response_data(
                    message="Password or Email Incorrect.",
                    status=status.HTTP_400_BAD_REQUEST,
                    data=None,
                    # errors=e.detail,  # Provide detailed validation errors
                )
        return create_response_util.create_response_data(
                message="An error occurred",
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                data=None,
                # errors=str(e),  # Provide a general error message
            )
            

class UserProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request, format=None):
        serializer = UserProfileSerializer(request.user)
        
        return create_response_util.create_response_data(
                message="Success",
                status=status.HTTP_200_OK,
                data=(serializer.data),
                errors=None,
                )
        


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = ChangePasswordSerializer(data=request.data, context={'user': request.user, 'request': request})
        if serializer.is_valid():
            serializer.save()  # Ensure you call save to update the user password
            return create_response_util.create_response_data(
                message="Password changed successfully",
                status=status.HTTP_200_OK,
                data=serializer.data,
                errors=None,
            )
        return create_response_util.create_response_data(
            message="Password not match.",
            status=status.HTTP_400_BAD_REQUEST,
            data=None,
        )
      

 
class SendResetPasswordView(APIView):
    def post(self, request, format=None):
        serializer = SendResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            return create_response_util.create_response_data(
                    message="Password Reset Email Send successfully",
                    status=status.HTTP_200_OK,
                    data=serializer.data,
                    errors=None,
                )
        return create_response_util.create_response_data(
            message="Email Send fialed.",
            status=status.HTTP_400_BAD_REQUEST,
            data=None,
        )



class UserResetPasswordView(APIView):
    def post(self, request, uid, token, format=True):
        serializer = UserResetPasswordSerializer(data=request.data, 
                                                 context={'uid': uid, 'token': token})
        if serializer.is_valid():
            user = serializer.save()
            return Response(
                {
                    "status_code": 200,
                    "message": "Password Reset successfully",
                    "data": {},  # You can add user info here if needed
                    "errors": None
                },
                status=status.HTTP_200_OK
            )
        return Response(
            {
                "status_code": 400,
                "message": "Password Reset failed.",
                "data": None,
                "errors": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )
  



from rest_framework import status
from .models import BlacklistedToken

class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        token = request.auth  # Get the token from the request

        if not token:
            return Response({"error": "No token provided."}, status=status.HTTP_400_BAD_REQUEST)

        # Add the token to the blacklist
        BlacklistedToken.objects.get_or_create(token=token)

        return Response({"message": "Logged out successfully."}, status=status.HTTP_205_RESET_CONTENT)