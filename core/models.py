import random
import uuid
from datetime import date, timedelta

from dateutil.relativedelta import relativedelta

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class UserRole(models.TextChoices):
    ADMIN = "admin", "Admin"
    CUSTOMER = "customer", "Customer"
    TECHNICIAN = "technician", "Technician"


class User(AbstractUser):
    ROLE_CHOICES = (
        ("admin", "Admin"),
        ("customer", "Customer"),
        ("technician", "Technician"),
    )
    role = models.CharField(max_length=20, choices=UserRole.choices, default=UserRole.CUSTOMER)
    dob = models.DateField(null=True, blank=True)
    address = models.TextField(blank=True)
    telephone = models.CharField(max_length=15, blank=True)
    gender = models.CharField(max_length=10, blank=True)
    last_2fa_verified = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.username} ({self.role})"

    @property
    def all_bills(self):
        return Bill.objects.filter(meter__owner=self)

    def soft_delete(self):
        self.is_active = False
        self.save()


class TwoFactorCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_expired(self):
        return timezone.now() > self.expires_at

    @staticmethod
    def generate_code():
        return f"{random.randint(100000, 999999)}"


def generate_token():
    return str(uuid.uuid4()).replace("-", "")[:10]


class Meter(models.Model):
    METER_STATUS = (
        ("active", "Active"),
        ("inactive", "Inactive"),
        ("disconnected", "Disconnected"),
        ("flagged", "Flagged"),
    )
    meter_number = models.CharField(max_length=50, unique=True, db_index=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="meters")
    location = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=METER_STATUS, default="active")
    installed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="installed_meters",
    )
    date_installed = models.DateField(auto_now_add=True)
    credit_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)

    def __str__(self):
        return f"Meter {self.meter_number} - {self.owner.username}"


class Transaction(models.Model):
    meter = models.ForeignKey(Meter, on_delete=models.CASCADE, related_name="transactions")
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    token = models.CharField(max_length=20, default=generate_token, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_applied = models.BooleanField(default=False)
    expiry_date = models.DateTimeField(null=True, blank=True)

    def apply_token(self):
        if self.is_applied:
            return

        if self.meter.status in ["disconnected", "flagged"]:
            raise Exception("Cannot apply token to a disconnected or flagged meter.")

        self.meter.credit_balance += self.amount
        self.meter.save()

        unpaid_bills = Bill.objects.filter(meter=self.meter, status="pending").order_by("due_date")
        remaining_amount = self.amount
        for bill in unpaid_bills:
            if remaining_amount >= bill.amount_due:
                remaining_amount -= bill.amount_due
                bill.status = "paid"
                bill.amount_due = 0
                bill.save()
            elif remaining_amount > 0:
                bill.amount_due -= remaining_amount
                remaining_amount = 0
                bill.save()
                break

        self.is_applied = True
        self.save()

        TokenAuditLog.objects.create(
            transaction=self,
            meter=self.meter,
            amount=self.amount,
            applied_by=self.meter.owner,
        )

    def save(self, *args, **kwargs):
        if not self.expiry_date:
            self.expiry_date = timezone.now() + timedelta(days=7)
        super().save(*args, **kwargs)

    def is_expired(self):
        return self.expiry_date and timezone.now() > self.expiry_date

    def __str__(self):
        return f"Transaction {self.token} - {self.amount} GHS"


class ComplaintStatus(models.Model):
    name = models.CharField(max_length=50)

    def __str__(self):
        return self.name


class Complaint(models.Model):
    customer = models.ForeignKey(User, on_delete=models.CASCADE, related_name="complaints")
    technician = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_complaints",
    )
    subject = models.CharField(max_length=255)
    message = models.TextField()
    status = models.ForeignKey(ComplaintStatus, on_delete=models.SET_NULL, null=True, blank=True)
    priority = models.CharField(
        max_length=20,
        choices=[("low", "Low"), ("medium", "Medium"), ("high", "High")],
        default="medium",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        return f"Complaint by {self.customer.username}"


class Bill(models.Model):
    BILL_STATUS = (
        ("pending", "Pending"),
        ("paid", "Paid"),
    )
    PAYMENT_PLAN = (
        ("one_time", "One-Time"),
        ("installment", "Installment"),
    )

    meter = models.ForeignKey("Meter", on_delete=models.CASCADE, related_name="bills")
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)  # Full original amount
    amount_due = models.DecimalField(max_digits=10, decimal_places=2)  # Remaining balance
    plan_type = models.CharField(max_length=20, choices=PAYMENT_PLAN, default="one_time")

    # For installment plan only
    installment_months = models.IntegerField(default=0)
    due_date = models.DateField(null=True, blank=True, db_index=True)  # first due
    next_due_date = models.DateField(null=True, blank=True, db_index=True)  # next due

    status = models.CharField(max_length=20, choices=BILL_STATUS, default="pending", db_index=True)

    def __str__(self):
        return (
            f"Bill for {self.meter.meter_number} - {self.total_amount} GHS "
            f"({self.get_plan_type_display()})"
        )

    def setup_installment(self, months=12):
        if self.plan_type == "installment" and self.installment_months > 0:
            return  # Already configured
        self.plan_type = "installment"
        self.installment_months = months
        self.due_date = date.today() + relativedelta(months=1)
        self.next_due_date = self.due_date
        self.amount_due = self.total_amount
        self.save()

    def apply_payment(self, payment_amount):
        if self.status == "paid":
            return

        self.amount_due -= payment_amount

        if self.amount_due <= 0:
            self.amount_due = 0
            self.status = "paid"
            self.next_due_date = None
        elif self.plan_type == "installment":
            self.installment_months -= 1
            self.next_due_date = date.today() + relativedelta(months=1)

        self.save()

    @property
    def monthly_installment_amount(self):
        if self.plan_type == "installment" and self.installment_months:
            return round(self.total_amount / self.installment_months, 2)
        return None

    def save(self, *args, **kwargs):
        # Ensure created_at field is set
        if not self.pk:
            self.created_at = timezone.now()
        super().save(*args, **kwargs)


class TokenAuditLog(models.Model):
    transaction = models.ForeignKey(
        Transaction, on_delete=models.CASCADE, related_name="audit_logs"
    )
    meter = models.ForeignKey(Meter, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    applied_at = models.DateTimeField(auto_now_add=True)
    applied_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return f"AuditLog: {self.transaction.token} on {self.meter.meter_number}"


class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    user_snapshot = models.CharField(max_length=150, blank=True)  # store username even if deleted
    model_name = models.CharField(max_length=100)
    action = models.CharField(
        max_length=10,
        choices=(
            ("created", "Created"),
            ("updated", "Updated"),
            ("deleted", "Deleted"),
        ),
    )
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if self.user and not self.user_snapshot:
            self.user_snapshot = self.user.username
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.action.title()} {self.model_name} by {self.user_snapshot or 'Unknown'}"


class BlacklistedToken(models.Model):
    token = models.CharField(max_length=512, unique=True)
    blacklisted_at = models.DateTimeField(auto_now_add=True)
