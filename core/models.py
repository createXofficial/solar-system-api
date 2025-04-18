from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid

class User(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('customer', 'Customer'),
        ('technician', 'Technician'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='customer')


class Meter(models.Model):
    meter_number = models.CharField(max_length=50, unique=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='meters')
    location = models.CharField(max_length=255)
    status = models.CharField(max_length=20, default='active')
    installed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='installed_meters')
    date_installed = models.DateField(auto_now_add=True)
    credit_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)

    def __str__(self):
        return f"Meter {self.meter_number} - {self.owner.username}"


def generate_token():
    return str(uuid.uuid4()).replace('-', '')[:10]


class Transaction(models.Model):
    meter = models.ForeignKey(Meter, on_delete=models.CASCADE, related_name='transactions')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    token = models.CharField(max_length=20, default=generate_token, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Add credit to the meter
        self.meter.credit_balance += self.amount
        self.meter.save()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Transaction {self.token} - {self.amount} GHS"


class Complaint(models.Model):
    customer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='complaints')
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
