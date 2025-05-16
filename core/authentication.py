import datetime

import jwt

from django.conf import settings

from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication

from core.models import BlacklistedToken, User

ACCESS_TOKEN_LIFETIME = datetime.timedelta(minutes=15)
REFRESH_TOKEN_LIFETIME = datetime.timedelta(days=7)
TOKEN_RENEWAL_WINDOW = datetime.timedelta(minutes=5)


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None

        try:
            prefix, token = auth_header.split()
            if prefix.lower() not in ("token", "bearer", "basic"):
                raise exceptions.AuthenticationFailed("Invalid token prefix")
        except ValueError:
            raise exceptions.AuthenticationFailed("Invalid authorization header format")

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed("Access token expired")
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed("Invalid access token")

        user = self.get_user_from_payload(payload)
        request.user = user

        exp = datetime.datetime.fromtimestamp(payload["exp"])
        now_utc = datetime.datetime.utcnow()
        if (exp - now_utc) < TOKEN_RENEWAL_WINDOW:
            new_tokens = self.generate_tokens(
                user, two_fa_verified=payload.get("2fa_verified", False)
            )
            request.META["RENEWED_TOKEN"] = new_tokens["access"]

        return (user, token)

    def get_user_from_payload(self, payload):
        try:
            user = User.objects.get(id=payload["user_id"])
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed("User not found")
        return user

    @staticmethod
    def generate_tokens(user, two_fa_verified=False):
        """
        Generate both access and refresh tokens.
        """
        now_utc = datetime.datetime.utcnow()
        access_payload = {
            "user_id": user.id,
            "exp": now_utc + ACCESS_TOKEN_LIFETIME,
            "iat": now_utc,
            "2fa_verified": two_fa_verified,
            "type": "access",
        }

        refresh_payload = {
            "user_id": user.id,
            "exp": now_utc + REFRESH_TOKEN_LIFETIME,
            "iat": now_utc,
            "type": "refresh",
        }

        access_token = jwt.encode(access_payload, settings.SECRET_KEY, algorithm="HS256")
        refresh_token = jwt.encode(refresh_payload, settings.SECRET_KEY, algorithm="HS256")

        return {"access": access_token, "refresh": refresh_token}

    @staticmethod
    def refresh_access_token(refresh_token):
        if BlacklistedToken.objects.filter(token=refresh_token).exists():
            raise exceptions.AuthenticationFailed("Token has been revoked")
        try:
            payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=["HS256"])
            if payload.get("type") != "refresh":
                raise exceptions.AuthenticationFailed("Invalid token type for refresh")
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed("Refresh token expired")
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed("Invalid refresh token")

        user = User.objects.get(id=payload["user_id"])
        return JWTAuthentication.generate_tokens(user, two_fa_verified=True)
