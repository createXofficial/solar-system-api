import logging
import uuid
from datetime import timedelta

import jwt

import jwt.utils
from rest_framework_simplejwt.tokens import RefreshToken

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, logout, tokens
from django.core.mail import send_mail
from django.db.models import Q
from django.urls import reverse
from django.utils import encoding, timezone
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode


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
from .utils import get_changes, log_action


logger = logging.getLogger(__name__)

User = get_user_model()

SESSION_TIMEOUT_MINUTES = 30
TWO_FA_VALIDITY_MINUTES = 15


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        user = authenticate(username=email, password=password)

        if user:
            # Check if 2FA is required
            now = timezone.now()
            if not user.last_2fa_verified or (now - user.last_2fa_verified).total_seconds() > 86400:
                # Generate and send 2FA code
                code = TwoFactorCode.generate_code()
                expires_at = now + timedelta(minutes=10)
                TwoFactorCode.objects.create(user=user, code=code, expires_at=expires_at)
                user.email_user(
                    "Your 2FA Code",
                    f"Hello {user.get_short_name()},\n\nYour verification code is: {code}"
                    f"\n\nThis code is valid for 10 minutes.\n\nThank you!",
                    "oswald.osei16@gmail.com",
                    fail_silently=False,
                )
                serializer = UserSerializer(user)

                return Response(
                    {
                        "responseCode": "001",
                        "responseMessage": "2FA code sent to your email.",
                        "user": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                # Issue tokens
                refresh = RefreshToken.for_user(user)
                log_action(
                    user=user,
                    model_name="User",
                    action="login",
                    description="User login successful",
                )

                return Response(
                    {
                        "responseCode": "000",
                        "responseMessage": "User login successful",
                        "data": {
                            "user": UserSerializer(user).data,
                            "access": str(refresh.access_token),
                            "refresh": str(refresh),
                        },
                    },
                    status=status.HTTP_200_OK,
                )

        return Response(
            {
                "responseCode": "111",
                "responseMessage": "Invalid credentials.",
            }
        )


class TwoFactorVerifyView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        code = request.data.get("code")
        try:
            user = User.objects.get(email=email)
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
                log_action(
                    user=user,
                    model_name="User",
                    action="Login",
                    description="User verified 2FA and logged in",
                )

                return Response(
                    {
                        "responseCode": "000",
                        "responseMessage": "User login successful",
                        "data": {
                            "user": UserSerializer(user).data,
                            "access": str(refresh.access_token),
                            "refresh": str(refresh),
                        },
                    },
                    status=status.HTTP_200_OK,
                )

            else:
                return Response(
                    {
                        "responseCode": "111",
                        "responseMessage": "Invalid or expired 2FA code.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except User.DoesNotExist:
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "User not found.",
                    "data": {"detail": "User not found."},
                },
                status=status.HTTP_404_NOT_FOUND,
            )



class LogoutView(APIView):
    def post(self, request):
        refresh_token = request.data.get("refresh")
        user = self.request.user
        if not refresh_token:
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "User logout failed",
                    "data": {"detail": "Refresh token required"},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not user.is_authenticated:
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "User logout failed",
                    "data": {"detail": "User not authenticated"},
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Decode to check validity
        try:
            jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return Response({"error": "Invalid token"}, status=400)

        # Save to blacklist
        BlacklistedToken.objects.create(token=refresh_token)

        log_action(user=user, model_name="User", action="logout", description="User Logged out")

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

                        "responseCode": "111",
                        "responseMessage": "Session error",
                        "data": {
                            "authenticated": False,
                            "detail": "Session error. Please log in again.",
                        },
                    }
                )
            if inactive_time > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
                logout(request)
                return Response(
                    {
                        "responseCode": "111",
                        "responseMessage": "Session error",
                        "data": {
                            "authenticated": False,
                            "detail": "Session expired. Please log in again.",
                        },
                    }
                )

        request.session["last_active"] = timezone.now().isoformat()
        return Response(
            {
                "responseCode": "000",
                "responseMessage": "Session active",
                "data": {
                    "detail": "Session is active.",
                    "last_active": request.session["last_active"],
                },
            }
        )


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "User with this email does not exist.",
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        reset_token = str(uuid.uuid4())
        request.session[f"password_reset_token_{email}"] = reset_token

        uidb64 = urlsafe_base64_encode(encoding.force_bytes(user.pk))
        token = tokens.default_token_generator.make_token(user)
        reset_link = request.build_absolute_uri(
            reverse("password-reset-confirm", kwargs={"uidb64": uidb64, "token": token})
        )

        user.email_user(
            "Password Reset Request",
            f"Click the link below to reset your password:\n{reset_link}",
            # [email],
            "oswald.osei16@gmail.com",
            fail_silently=False,
        )
        logger.warning(f"Password reset requested for email: {email}")
        log_action(
            user=user,
            model_name="User",
            action="password_reset",
            description=f"Password reset requested for {email}",
        )
        return Response(
            {
                "responseCode": "000",
                "responseMessage": f"password reset link sent to {email}",
            },
            status=status.HTTP_200_OK,
        )


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_password = serializer.validated_data["new_password"]
        if not new_password:
            return Response(
                {"detail": "New password is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "User not found.",
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        if not tokens.default_token_generator.check_token(user, token):
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "Invalid or expired token.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(new_password)
        user.save()

        # Log to audit trail
        log_action(
            user=user,
            model_name="User",
            action="password_reset",
            description=f"Password reset for {user.email}",
        )

        del request.session[f"password_reset_token_{user.email}"]
        return Response(
            {
                "responseCode": "000",
                "responseMessage": "Password reset successful.",
            },
            status=status.HTTP_200_OK,
        )


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]


class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            if not request.user.check_password(serializer.data["old_password"]):
                return Response(
                    {
                        "responseCode": "111",
                        "responseMessage": "Password change failed, old password is incorrect",
                    },
                    status=400,
                )

            request.user.set_password(serializer.data["new_password"])
            request.user.save()

            # Log the successful password change
            log_action(
                user=request.user,
                model_name="User",
                action="password_changed",  # or "updated" if you prefer
                description="User changed their password",
            )

            return Response(
                {
                    "responseCode": "000",
                    "responseMessage": "Password changed successfully.",
                },
                status=200,
            )

        return Response(
            {
                "responseCode": "111",
                "responseMessage": "Password change failed",
                "data": serializer.errors,
            },
            status=400,
        )


class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.role == "admin":
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "Permission denied",
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        users = User.objects.all().order_by("-date_joined")

        # Filter by role (admin, customer, technician)
        role = request.query_params.get("role")
        if role in ["admin", "customer", "technician"]:
            users = users.filter(role=role)

        # Search by first name, last name or email
        search = request.query_params.get("search")
        if search:
            users = users.filter(
                Q(first_name__icontains=search)
                | Q(last_name__icontains=search)
                | Q(email__icontains=search)
            )
        serializer = UserSerializer(users, many=True)
        return Response(
            {"responseCode": "000", "responseMessage": "User list", "data": serializer.data},
            status=status.HTTP_200_OK,
        )


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

            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "User not found.",
                },
                status=404,
            )
        if request.user != user and request.user.role != "admin":
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "Permission denied",
                },
                status=403,
            )
        serializer = UserSerializer(user)
        return Response(
            {
                "responseCode": "000",
                "responseMessage": "User details",
                "data": serializer.data,
            },
            status=200,
        )

    def put(self, request, user_id):
        user = self.get_object(user_id)
        if not user:
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "User not found.",
                },
                status=404,
            )
        if request.user != user and request.user.role != "admin":
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "Permission denied",
                },
                status=403,
            )

        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            # Prevent email/phone duplication
            phone = serializer.validated_data.get("phone")
            email = serializer.validated_data.get("email")

            if phone and User.objects.filter(phone=phone).exclude(id=user.id).exists():
                return Response(
                    {
                        "responseCode": "111",
                        "responseMessage": "User with same Phone Number exists.",
                    },
                    status=400,
                )
            if email and User.objects.filter(email=email).exclude(id=user.id).exists():
                return Response(
                    {
                        "responseCode": "111",
                        "responseMessage": "User with same email exists.",
                    },
                    status=400,
                )

            old_user = User.objects.get(pk=user.id)  # fresh from DB
            new_data = serializer.validated_data
            changes = get_changes(old_user, new_data)
            serializer.save()
            # Log the update
            log_action(
                user=user,
                model_name="User",
                action="updated",
                description=f"Updated user {user.get_short_name()}",
                metadata=changes,
            )
            return Response(
                {"responseCode": "000", "responseMessage": "User updated", "data": serializer.data},
                status=200,
            )

        return Response(
            {
                "responseCode": "111",
                "responseMessage": "User update failed",
                "data": serializer.errors,
            },
            status=400,
        )

    def delete(self, request, user_id):
        user = self.get_object(user_id)
        if not user:
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "User not found.",
                },
                status=404,
            )
        # Admins can delete any user, but users can only delete their own account
        if request.user != user and request.user.role != "admin":
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "Permission denied",
                },
                status=403,
            )
        # Prevent deletion of admin account
        if user.role == "admin":
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "Cannot delete admin account",
                },
                status=400,
            )
        # Prevent deletion of self account
        if request.user == user:
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "Cannot delete your own account",
                },
                status=400,
            )
        # Prevent deletion of superuser account
        if user.is_superuser:
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "Cannot delete superuser account",
                },
                status=400,
            )
        # Log the deletion

        # Delete the user
        user.delete()

        log_action(
            user=user,
            model_name="User",
            action="deleted",
            description=f"Deleted user {user.get_short_name()}",
        )
        return Response(
            {
                "responseCode": "000",
                "responseMessage": "User deleted.",
            },
            status=204,
        )


class RefreshTokenView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "Token refresh failed",
                },
                status=status.HTTP_400_BAD_REQUEST,

            )

        try:
            tokens = JWTAuthentication.refresh_access_token(refresh_token)
        except Exception as e:
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": f"Token refresh failed,{e}) ",
                    "detail": str(e),
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        return Response(tokens, status=status.HTTP_200_OK)
