from django.urls import include, path

from rest_framework.routers import DefaultRouter

# ViewSets
from .views import (
    ApplyTokenView,
    BillViewSet,
    ComplaintViewSet,
    CustomerViewSet,
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
    RegisterView,
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
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("auth/change-password/", ChangePasswordView.as_view(), name="change-password"),
    path("auth/password-reset/", ForgotPasswordView.as_view(), name="password-reset"),
    path(
        "auth/password-reset-confirm/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password-reset-confirm",
    ),
    # Token
    path("apply-token/", ApplyTokenView.as_view(), name="apply-token"),
]
