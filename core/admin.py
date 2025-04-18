from django.contrib import admin
from .models import TokenAuditLog, User, Meter, Transaction, Complaint, Bill
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'role', 'is_active')
    search_fields = ('username', 'email')
    list_filter = ('role',)

@admin.register(Meter)
class MeterAdmin(admin.ModelAdmin):
    list_display = ('meter_number', 'owner', 'location', 'status', 'credit_balance')
    search_fields = ('meter_number', 'owner__username')
    list_filter = ('status',)

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('token', 'meter', 'amount', 'created_at', 'is_applied')
    search_fields = ('token', 'meter__meter_number')
    list_filter = ('created_at', 'is_applied')

@admin.register(Complaint)
class ComplaintAdmin(admin.ModelAdmin):
    list_display = ('customer', 'technician', 'subject', 'status', 'created_at')
    search_fields = ('customer__username', 'subject')
    list_filter = ('status',)

@admin.register(Bill)
class BillAdmin(admin.ModelAdmin):
    list_display = ('meter', 'amount_due', 'due_date', 'status')
    search_fields = ('meter__meter_number',)
    list_filter = ('status', 'due_date')

@admin.register(TokenAuditLog)
class TokenAuditLogAdmin(admin.ModelAdmin):
    list_display = ('transaction', 'meter', 'amount', 'applied_at', 'applied_by')
    search_fields = ('transaction__token', 'meter__meter_number', 'applied_by__username')
    list_filter = ('applied_at',)
