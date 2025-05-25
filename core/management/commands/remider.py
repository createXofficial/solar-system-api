from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand
from django.db.models import Min, Sum
from django.utils import timezone

from core.models import Bill, User


class Command(BaseCommand):
    help = "Send email reminders to debtors with upcoming due dates"

    def handle(self, *args, **kwargs):
        today = timezone.now().date()
        tomorrow = today + timedelta(days=1)
        next_week = today + timedelta(days=7)

        target_ranges = {
            "today": today,
            "tomorrow": tomorrow,
            "week": (today, next_week),
        }

        for label, date_filter in target_ranges.items():
            if isinstance(date_filter, tuple):
                bills = Bill.objects.filter(status="pending", due_date__range=date_filter)
            else:
                bills = Bill.objects.filter(status="pending", due_date=date_filter)

            customers = User.objects.filter(role="customer", meter__bills__in=bills).distinct()

            for customer in customers:
                unpaid_bills = bills.filter(meter__owner=customer)

                total_due = unpaid_bills.aggregate(total=Sum("amount_due"))["total"] or 0
                due_date = unpaid_bills.aggregate(soonest=Min("due_date"))["soonest"]

                if total_due == 0 or not due_date:
                    continue  # skip if nothing to pay

                subject = "⚠️ Bill Payment Reminder"
                message = (
                    f"Dear {customer.first_name},\n\n"
                    f"You have unpaid bills totaling ₦{total_due:.2f} "
                    f"with the next due date on {due_date.strftime('%Y-%m-%d')}.\n"
                    f"Please make your payment to avoid service disruption.\n\n"
                    f"Thank you."
                )

                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [customer.email],
                    fail_silently=False,
                )

                self.stdout.write(f"Reminder sent to {customer.email} for {label}")
