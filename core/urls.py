from django.urls import include, path

from rest_framework.routers import DefaultRouter

# ViewSets
from .views import (
    ApplyTokenView,
    AuditLogViewSet,
    BillViewSet,
    ComplaintViewSet,
    CustomerViewSet,
    DebtorsViewSet,
    MeterViewSet,
    TokenAuditLogViewSet,
    TransactionViewSet,
)

# Auth Views
from .views_auth import (
    ChangePasswordView,
    ForgotPasswordView,
    LoginView,
    LogoutView,
    PasswordResetConfirmView,
    RefreshTokenView,
    RegisterView,
    SessionCheckView,
    TwoFactorVerifyView,
    UserDetailUpdateDeleteView,
    UserListView,
)

# ----------------- Routers -------------------
router = DefaultRouter()
router.register(r"meters", MeterViewSet, basename="meter")
router.register(r"transactions", TransactionViewSet, basename="transaction")
router.register(r"complaints", ComplaintViewSet, basename="complaint")
router.register(r"bills", BillViewSet, basename="bill")
router.register(r"customers", CustomerViewSet, basename="customer")  # pluralize for clarity
router.register(r"token-logs", TokenAuditLogViewSet, basename="tokenlog")

# ----------------- URL Patterns -------------------
urlpatterns = [
    path("", include(router.urls)),
    # Auth & Account
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/2fa-verify/", TwoFactorVerifyView.as_view(), name="2fa-verify"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("auth/change-password/", ChangePasswordView.as_view(), name="change-password"),
    path("auth/password-reset/", ForgotPasswordView.as_view(), name="password-reset"),
    path(
        "auth/password-reset-confirm/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password-reset-confirm",
    ),
    path("auth/token/refresh/", RefreshTokenView.as_view(), name="token_refresh"),

    path("auth/session-check/", SessionCheckView.as_view(), name="session-check"),

    # Token
    path("apply-token/", ApplyTokenView.as_view(), name="apply-token"),
    # Users
    path("users/<int:user_id>/", UserDetailUpdateDeleteView.as_view(), name="user-detail"),
    path("users/", UserListView.as_view(), name="user-list"),
    path("debtors/", DebtorsViewSet.as_view({"get": "list"}), name="debtor-list"),

    # audit logs
    path("audit-logs/", AuditLogViewSet.as_view({"get": "list"}), name="auditlog"),
]
