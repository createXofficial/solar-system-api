from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver
from django.utils.timezone import now

from .models import Bill, ChangeLog, Complaint, Meter, Transaction, User

MONITORED_MODELS = [User, Meter, Transaction, Complaint, Bill]


def get_instance_description(instance):
    return str(instance)


@receiver(post_save)
def log_create_or_update(sender, instance, created, **kwargs):
    if sender not in MONITORED_MODELS:
        return

    ChangeLog.objects.create(
        user=getattr(instance, "owner", None) or getattr(instance, "customer", None),
        model_name=sender.__name__,
        action="created" if created else "updated",
        description=get_instance_description(instance),
        timestamp=now(),
    )


@receiver(post_delete)
def log_delete(sender, instance, **kwargs):
    if sender not in MONITORED_MODELS:
        return

    ChangeLog.objects.create(
        user=getattr(instance, "owner", None) or getattr(instance, "customer", None),
        model_name=sender.__name__,
        action="deleted",
        description=get_instance_description(instance),
        timestamp=now(),
    )
