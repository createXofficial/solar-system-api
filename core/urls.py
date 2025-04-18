from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import MeterViewSet, TransactionViewSet, ComplaintViewSet, BillViewSet

router = DefaultRouter()
router.register(r'meters', MeterViewSet, basename='meter')
router.register(r'transactions', TransactionViewSet, basename='transaction')
router.register(r'complaints', ComplaintViewSet, basename='complaint')
router.register(r'bills', BillViewSet, basename='bill')

urlpatterns = [
    path('', include(router.urls)),
]

from .views_auth import password_reset_request, reset_password_confirm
urlpatterns += [
    path('password-reset/', password_reset_request),
    path('password-reset-confirm/<uidb64>/<token>/', reset_password_confirm),
]