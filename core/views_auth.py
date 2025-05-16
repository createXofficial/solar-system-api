import logging
import uuid
from datetime import timedelta

import jwt
from rest_framework_simplejwt.tokens import RefreshToken

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, logout
from django.core.mail import send_mail
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone

from rest_framework import generics, permissions, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.authentication import JWTAuthentication

from .models import BlacklistedToken, TwoFactorCode
from .serializers import (
    ChangePasswordSerializer,
    EmailSerializer,
    PasswordResetSerializer,
    RegisterSerializer,
    UserSerializer,
)
from .utils import create_audit_log

logger = logging.getLogger(__name__)

User = get_user_model()

SESSION_TIMEOUT_MINUTES = 30
TWO_FA_VALIDITY_MINUTES = 15


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)
        if user:
            # Check if 2FA is required
            now = timezone.now()
            if not user.last_2fa_verified or (now - user.last_2fa_verified).total_seconds() > 86400:
                # Generate and send 2FA code
                code = TwoFactorCode.generate_code()
                expires_at = now + timedelta(minutes=10)
                TwoFactorCode.objects.create(user=user, code=code, expires_at=expires_at)
                send_mail(
                    "Your 2FA Code",
                    f"Your verification code is: {code}",
                    "no-reply@solarsys.com",
                    [user.email],
                    fail_silently=False,
                )
                return Response(
                    {"detail": "2FA code sent to your email."},
                    status=status.HTTP_200_OK,
                )
            else:
                # Issue tokens
                refresh = RefreshToken.for_user(user)
                create_audit_log(
                    user=user,
                    model_name="User",
                    action="login",
                    description=f"User {user.username} logged in",
                )
                return Response(
                    {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    status=status.HTTP_200_OK,
                )
        return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)


class TwoFactorVerifyView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username")
        code = request.data.get("code")
        try:
            user = User.objects.get(username=username)
            two_fa = (
                TwoFactorCode.objects.filter(user=user, code=code).order_by("-created_at").first()
            )
            if two_fa and not two_fa.is_expired():
                # Update last 2FA verified time
                user.last_2fa_verified = timezone.now()
                user.save()
                # Delete used code
                two_fa.delete()
                # Issue tokens
                refresh = RefreshToken.for_user(user)
                return Response(
                    {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"detail": "Invalid or expired 2FA code."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)


class LogoutView(APIView):
    def post(self, request):
        refresh_token = request.data.get("refresh")
        user = request.user
        if not refresh_token:
            return Response({"error": "Refresh token required"}, status=400)

        # Decode to check validity
        try:
            jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return Response({"error": "Invalid token"}, status=400)

        # Save to blacklist
        BlacklistedToken.objects.create(token=refresh_token)
        create_audit_log(
            user=user,
            model_name="User",
            action="login",
            description=f"User {user.username} logged out",
        )
        return Response({"detail": "Logged out successfully."})


class SessionCheckView(APIView):
    def get(self, request):
        if not request.user.is_authenticated:
            return Response({"authenticated": False})

        last_active = request.session.get("last_active")
        if last_active:
            try:
                inactive_time = timezone.now() - timezone.datetime.fromisoformat(last_active)
            except Exception as e:
                logger.warning(f"Session parse error: {e}")
                logout(request)
                return Response(
                    {
                        "authenticated": False,
                        "detail": "Session error. Please log in again.",
                    }
                )
            if inactive_time > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
                logout(request)
                return Response(
                    {
                        "authenticated": False,
                        "detail": "Session expired. Please log in again.",
                    }
                )

        request.session["last_active"] = timezone.now().isoformat()
        return Response({"authenticated": True})


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"detail": "User with this email does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )

        reset_token = str(uuid.uuid4())
        request.session[f"password_reset_token_{email}"] = reset_token
        reset_link = (
            request.build_absolute_uri(reverse("password-reset-confirm"))
            + f"?email={email}&token={reset_token}"
        )

        send_mail(
            "Password Reset Request",
            f"Click the link below to reset your password:\n{reset_link}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        logger.warning(f"Password reset requested for email: {email}")
        return Response({"detail": "Password reset link sent to your email."})


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        token = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        session_token = request.session.get(f"password_reset_token_{email}")
        if session_token != token:
            return Response(
                {"detail": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        user.set_password(new_password)
        user.save()

        del request.session[f"password_reset_token_{email}"]
        return Response({"detail": "Password reset successful."})


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]


class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            if not request.user.check_password(serializer.data["old_password"]):
                return Response({"old_password": "Wrong password."}, status=400)
            request.user.set_password(serializer.data["new_password"])
            request.user.save()
            return Response({"status": "Password updated."})
        return Response(serializer.errors, status=400)


class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.role == "admin":
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

        users = User.objects.all().order_by("-date_joined")

        # Filter by role (admin, customer, technician)
        role = request.query_params.get("role")
        if role in ["admin", "customer", "technician"]:
            users = users.filter(role=role)

        # Search by username or email
        search = request.query_params.get("search")
        if search:
            users = users.filter(Q(username__icontains=search) | Q(email__icontains=search))
        serialer = UserSerializer(users, many=True)
        return Response(serialer.data)


class UserDetailUpdateDeleteView(APIView):
    """
    Admins can update/delete any user.
    Authenticated users can only view/update/delete their own account.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, user_id):
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

    def get(self, request, user_id):
        user = self.get_object(user_id)
        if not user:
            return Response({"detail": "User not found."}, status=404)
        if request.user != user and request.user.role != "admin":
            return Response({"detail": "Not allowed."}, status=403)
        serializer = UserSerializer(user)
        return Response(serializer.data)

    def put(self, request, user_id):
        user = self.get_object(user_id)
        if not user:
            return Response({"detail": "User not found."}, status=404)
        if request.user != user and request.user.role != "admin":
            return Response({"detail": "Not allowed."}, status=403)

        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            # Prevent email/username duplication
            username = serializer.validated_data.get("username")
            email = serializer.validated_data.get("email")

            if username and User.objects.filter(username=username).exclude(id=user.id).exists():
                return Response({"username": "Username already exists."}, status=400)
            if email and User.objects.filter(email=email).exclude(id=user.id).exists():
                return Response({"email": "Email already exists."}, status=400)

            serializer.save()
            create_audit_log(
                user=request.user,
                model_name="User",
                action="updated",
                description=f"Updated user {user.username}",
                object_id=user.id,
            )
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, user_id):
        user = self.get_object(user_id)
        if not user:
            return Response({"detail": "User not found."}, status=404)
        if request.user != user and request.user.role != "admin":
            return Response({"detail": "Not allowed."}, status=403)
        user.soft_delete()
        create_audit_log(
            user=request.user,
            model_name="User",
            action="deleted",
            description=f"Deleted user {user.username}",
            object_id=user.id,
        )
        return Response({"detail": "User deleted."}, status=204)


class RefreshTokenView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response(
                {"detail": "Refresh token required"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            tokens = JWTAuthentication.refresh_access_token(refresh_token)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(tokens, status=status.HTTP_200_OK)
