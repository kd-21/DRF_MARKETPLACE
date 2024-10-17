from rest_framework import serializers
from accounts.models import User
from rest_framework.exceptions import ValidationError
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .models import User
from .utils import Util
from django.contrib.auth import get_user_model


User = get_user_model()

class UserSignUpSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    user_type = serializers.ChoiceField(choices=[
        ('BUYER', 'Buyer'),
        ('SELLER', 'Seller')
    ])

    class Meta:
        model = User
        fields = ['email', 'password', 'confirm_password', 'user_type']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        
        if password != confirm_password:
            raise serializers.ValidationError('Passwords do not match.')
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password')  
        user_type = validated_data.pop('user_type')  # Get user_type

        # Create user without user_type
        user = User.objects.create_user(**validated_data)
        user.user_type = user_type  # Set user_type
        user.save()  # Save the user again to include user_type

        return user



    
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email','password']
        
        
        
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'user_type','created_at','modified_at','contact']
        


class ChangePasswordSerializer(serializers.Serializer):  # Use Serializer instead of ModelSerializer
    old_password = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        if attrs['password'] == attrs['old_password']:
            raise serializers.ValidationError({"Password": "New password Must Be Defferent From old password"})
        return attrs

    def validate_old_password(self, value):
        user = self.context['user']
        if not user.check_password(value):
            raise serializers.ValidationError({"old_password": "Old password is not correct"})
        return value

    def save(self):
        user = self.context['user']
        user.set_password(self.validated_data['password'])
        user.save()
        
        

class SendResetPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, required=True)
    
    class Meta:
        model = User
        fields = ['email',]
        
    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('encode UID',uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('token reset pass', token)
            link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
            print('password linke',link)
            # Send Email Logic
            body = 'Click following link to reset your password '+link
            data = {
                'subject': 'Reset Your Password',
                'body': f'Click the link to reset your password: <a href="{link}">{link}</a>',
                'to_email': user.email,
                'reset_link': link
            }
            Util.send_email(data)
            return attrs
        else:
            raise ValidationError('Your are not Register')        
    
    
class UserResetPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['password', 'password2']

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs 

    def save(self):
        try:
            uid = self.context.get('uid')
            token = self.context.get('token')
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError({'detail': 'Token is not valid or expired.'})

            user.set_password(self.validated_data['password'])
            user.save()
            return user  # Return the user or any relevant info
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationError({'detail': 'Token is not valid or expired.'})
