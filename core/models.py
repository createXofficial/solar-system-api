from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib import admin
import uuid

class User(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('customer', 'Customer'),
        ('technician', 'Technician'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='customer')

    @property
    def all_bills(self):
        return Bill.objects.filter(meter__owner=self)


class Meter(models.Model):
    METER_STATUS = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('disconnected', 'Disconnected'),
    )
    meter_number = models.CharField(max_length=50, unique=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='meters')
    location = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=METER_STATUS, default='active')
    installed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='installed_meters')
    date_installed = models.DateField(auto_now_add=True)
    credit_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)

    def __str__(self):
        return f"Meter {self.meter_number} - {self.owner.username}"


def generate_token():
    return str(uuid.uuid4()).replace('-', '')[:16]


class Transaction(models.Model):
    meter = models.ForeignKey(Meter, on_delete=models.CASCADE, related_name='transactions')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    token = models.CharField(max_length=20, default=generate_token, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_applied = models.BooleanField(default=False)

    def apply_token(self):
        if self.is_applied:
            return
        if self.meter.status == 'disconnected':
            raise Exception("Cannot apply token to a disconnected meter.")

        self.meter.credit_balance += self.amount
        self.meter.save()

        unpaid_bills = Bill.objects.filter(meter=self.meter, status='pending').order_by('due_date')
        remaining_amount = self.amount
        for bill in unpaid_bills:
            if remaining_amount >= bill.amount_due:
                remaining_amount -= bill.amount_due
                bill.status = 'paid'
                bill.amount_due = 0
                bill.save()
            elif remaining_amount > 0:
                bill.amount_due -= remaining_amount
                remaining_amount = 0
                bill.save()
                break

        self.is_applied = True
        self.save()

        # Audit trail log
        TokenAuditLog.objects.create(
            transaction=self,
            meter=self.meter,
            amount=self.amount,
            applied_by=self.meter.owner
        )

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Transaction {self.token} - {self.amount} GHS"


class Complaint(models.Model):
    customer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='complaints')
    technician = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        limit_choices_to={'role': 'technician'}, 
        related_name='assigned_complaints'
        )
    subject = models.CharField(max_length=255)
    message = models.TextField()
    status = models.CharField(max_length=20, default='open')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Complaint by {self.customer.username}"


class Bill(models.Model):
    BILL_STATUS = (
        ('pending', 'Pending'),
        ('paid', 'Paid'),
    )
    meter = models.ForeignKey(Meter, on_delete=models.CASCADE, related_name='bills')
    amount_due = models.DecimalField(max_digits=10, decimal_places=2)
    due_date = models.DateField()
    status = models.CharField(max_length=20, choices=BILL_STATUS, default='pending')

    def __str__(self):
        return f"Bill for {self.meter.meter_number} - {self.amount_due} GHS"


class TokenAuditLog(models.Model):
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE, related_name='audit_logs')
    meter = models.ForeignKey(Meter, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    applied_at = models.DateTimeField(auto_now_add=True)
    applied_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return f"AuditLog: {self.transaction.token} on {self.meter.meter_number}"