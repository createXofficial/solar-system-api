from django.contrib import admin

from .models import (
    Bill,
    ChangeLog,
    Complaint,
    ComplaintStatus,
    Meter,
    TokenAuditLog,
    Transaction,
    User,
)


# 🔹 Inline Admin for TokenAuditLog under Transaction
class TokenAuditLogInline(admin.TabularInline):
    model = TokenAuditLog
    extra = 0
    readonly_fields = ("meter", "amount", "applied_at", "applied_by")


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "role", "is_active")
    search_fields = ("username", "email")
    list_filter = ("role",)


@admin.register(Meter)
class MeterAdmin(admin.ModelAdmin):
    list_display = ("meter_number", "owner", "location", "status", "credit_balance")
    search_fields = ("meter_number", "owner__username")
    list_filter = ("status",)

    # 🔹 Fieldsets for better field grouping
    fieldsets = (
        ("Meter Info", {"fields": ("meter_number", "owner", "location")}),
        ("Status & Balance", {"fields": ("status", "credit_balance")}),
    )


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ("token", "meter", "amount", "created_at", "is_applied")
    search_fields = ("token", "meter__meter_number")
    list_filter = ("created_at", "is_applied")

    # 🔹 Inline TokenAuditLog entries for each transaction
    inlines = [TokenAuditLogInline]


# 🔹 Custom admin action to mark complaints as resolved
@admin.action(description="Mark selected complaints as resolved")
def mark_resolved(modeladmin, request, queryset):
    queryset.update(status="Resolved")


@admin.register(Complaint)
class ComplaintAdmin(admin.ModelAdmin):
    list_display = ("customer", "technician", "subject", "status", "created_at")
    search_fields = ("customer__username", "subject")
    list_filter = ("status",)
    actions = [mark_resolved]


@admin.register(Bill)
class BillAdmin(admin.ModelAdmin):
    list_display = ("meter", "amount_due", "due_date", "status")
    search_fields = ("meter__meter_number",)
    list_filter = ("status", "due_date")


@admin.register(TokenAuditLog)
class TokenAuditLogAdmin(admin.ModelAdmin):
    list_display = ("transaction", "meter", "amount", "applied_at", "applied_by")
    search_fields = (
        "transaction__token",
        "meter__meter_number",
        "applied_by__username",
    )
    list_filter = ("applied_at",)

    # 🔹 Read-only for log/audit info
    readonly_fields = ("transaction", "meter", "amount", "applied_at", "applied_by")


@admin.register(ComplaintStatus)
class ComplaintStatusAdmin(admin.ModelAdmin):
    list_display = ("name",)


@admin.register(ChangeLog)
class ChangeLogAdmin(admin.ModelAdmin):
    list_display = ("model_name", "action", "user", "timestamp")
    search_fields = ("model_name", "user__username")
    list_filter = ("action", "timestamp")

    # 🔹 Read-only audit fields
    readonly_fields = ("model_name", "action", "user", "timestamp")
