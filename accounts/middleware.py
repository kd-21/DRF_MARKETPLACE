from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response
from .models import BlacklistedToken

class TokenBlacklistMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        auth = JWTAuthentication()
        try:
            validated_token = auth.get_validated_token(request)
            if BlacklistedToken.objects.filter(token=validated_token).exists():
                return Response({"error": "Token has been blacklisted."}, status=401)
        except Exception:
            pass

        response = self.get_response(request)
        return response