from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver
from django.utils.timezone import now

from core.middleware import get_current_user
from core.models import AuditLog, Bill, Complaint, Meter, Transaction, User

MONITORED_MODELS = [User, Meter, Transaction, Complaint, Bill]


def get_instance_description(instance):
    try:
        return str(instance)
    except:
        return f"{instance.__class__.__name__} (ID: {instance.pk})"


@receiver(post_save)
def log_create_or_update(sender, instance, created, **kwargs):
    if sender not in MONITORED_MODELS:
        return

    user = (
        get_current_user()
        or getattr(instance, "owner", None)
        or getattr(instance, "customer", None)
    )
