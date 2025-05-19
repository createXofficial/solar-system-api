import random
import string

from rest_framework_simplejwt.tokens import RefreshToken

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from .models import AuditLog, BlacklistedToken, TwoFactorCode


def generate_2fa_code(length=6):
    return "".join(random.choices(string.digits, k=length))


def send_2fa_email(email, code):
    subject = "Your 2FA Verification Code"
    message = f"Use the code below to verify your login:\n\n{code}\n\nCode expires in 10 minutes."
    from_email = settings.DEFAULT_FROM_EMAIL
    send_mail(subject, message, from_email, [email])


def get_or_create_2fa_record(user):
    record, _ = TwoFactorCode.objects.get_or_create(user=user)
    return record


def is_code_expired(tf_record):
    return timezone.now() > tf_record.expires_at


def create_jwt_pair_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


def invalidate_old_tokens(user):
    BlacklistedToken.objects.filter(user=user).delete()


from core.models import AuditLog


def log_action(
    user,
    model_name,
    action,
    description="",
    status=True,
    metadata=None,
):
    """Logs an action to the audit trail."""
    AuditLog.objects.create(
        user=user if user else None,
        success=status,
        model_name=model_name,
        action=action,
        description=description,
        metadata=metadata or {},
        timestamp=timezone.now(),
    )


def get_changes(old_instance, new_data):
    changes = {}
    for field, new_value in new_data.items():
        old_value = getattr(old_instance, field, None)
        if old_value != new_value:
            changes[field] = {"from": str(old_value), "to": str(new_value)}
    return changes


def generate_meter_token(transaction):
    """Simulate meter token generation logic."""
    seed = f"{transaction.id}{transaction.amount}{transaction.timestamp}".encode()
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
