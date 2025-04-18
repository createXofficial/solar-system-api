from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ApplyTokenView, CustomerViewSet,MeterViewSet, TransactionViewSet,TokenAuditLogViewSet, ComplaintViewSet, BillViewSet

router = DefaultRouter()
router.register(r'meters', MeterViewSet, basename='meter')
router.register(r'transactions', TransactionViewSet, basename='transaction')
router.register(r'complaints', ComplaintViewSet, basename='complaint')
router.register(r'bills', BillViewSet, basename='bill')
router.register(r'customer', CustomerViewSet, basename='customer')
router.register('token-logs', TokenAuditLogViewSet, basename='tokenlogs')


urlpatterns = [
    path('', include(router.urls)),
]

from .views_auth import password_reset_request, reset_password_confirm
urlpatterns += [
    path('password-reset/', password_reset_request),
    path('password-reset-confirm/<uidb64>/<token>/', reset_password_confirm),
     path('apply-token/', ApplyTokenView.as_view(), name='apply-token'),
]