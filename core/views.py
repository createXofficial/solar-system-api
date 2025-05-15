import logging

from django.utils import timezone

from rest_framework import status, views, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Bill, Complaint, Meter, TokenAuditLog, Transaction, User
from .permissions import IsCustomerOwner
from .serializers import (
    ApplyTokenSerializer,
    BillSerializer,
    ComplaintSerializer,
    MeterSerializer,
    TokenAuditLogSerializer,
    TransactionSerializer,
)

logger = logging.getLogger(__name__)


class ApplyTokenView(views.APIView):
    def post(self, request):
        serializer = ApplyTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]
        transaction = Transaction.objects.select_related("meter").get(token=token)
        if transaction.is_applied:
            logger.info(
                f"User {request.user.username} tried to apply token {token} "
                f"but it was already applied"
            )
            return Response(
                {"detail": "Token already applied."}, status=status.HTTP_400_BAD_REQUEST
            )
        transaction.apply_token()
        logger.info(f"User {request.user.username} applied token {token}")
        return Response(
            {
                "detail": "Token applied successfully.",
                "meter_credit": transaction.meter.credit_balance,
            },
            status=status.HTTP_200_OK,
        )


class MeterViewSet(viewsets.ModelViewSet):
    serializer_class = MeterSerializer
    permission_classes = [IsAuthenticated, IsCustomerOwner]

    def get_queryset(self):
        queryset = Meter.objects.all().order_by("id")
        user = self.request.user
        if user.role == "admin":
            return queryset
        return queryset.filter(owner=user)


class TransactionViewSet(viewsets.ModelViewSet):
    queryset = Transaction.objects.select_related("meter", "meter__owner").all().order_by("id")
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def apply(self, request, pk=None):
        try:
            transaction = self.get_object()
            transaction.apply_token()
            return Response({"message": "Token applied successfully."})
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class TokenAuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = TokenAuditLog.objects.all().order_by("id")
    serializer_class = TokenAuditLogSerializer
    permission_classes = [IsAuthenticated]


class ComplaintViewSet(viewsets.ModelViewSet):
    serializer_class = ComplaintSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Complaint.objects.select_related("customer", "technician").all().order_by("id")
        user = self.request.user
        if user.role == "admin":
            return queryset
        return queryset.filter(customer=user)

    def perform_create(self, serializer):
        serializer.save(customer=self.request.user)

    @action(detail=True, methods=["post"])
    def assign_technician(self, request, pk=None):
        tech_id = request.data.get("technician_id")
        try:
            complaint = self.get_queryset().get(pk=pk)
            technician = User.objects.get(pk=tech_id, role="technician")
            complaint.technician = technician
            complaint.save()
            logger.info(
                f"Technician {technician.username} "
                f"assigned to complaint({complaint}) "
                f"by user {request.user.username}"
            )
            return Response({"message": "Technician assigned"})
        except Exception as e:
            return Response({"error": str(e)}, status=400)


class BillViewSet(viewsets.ModelViewSet):
    serializer_class = BillSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ["status"]
    search_fields = ["meter__meter_number"]
    ordering_fields = ["due_date"]

    def get_queryset(self):
        queryset = Bill.objects.select_related("meter", "meter__owner").all().order_by("id")
        user = self.request.user
        if user.role == "admin":
            return queryset
        return queryset.filter(meter__owner=user)


class CustomerViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["get"])
    def meters(self, request):
        meters = Meter.objects.filter(owner=request.user)
        serializer = MeterSerializer(meters, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def bills(self, request, pk=None):
        try:
            meter = Meter.objects.get(pk=pk, owner=request.user)
        except Meter.DoesNotExist:
            return Response({"error": "Meter not found"}, status=404)
        bills = meter.bills.all().order_by("id")
        serializer = BillSerializer(bills, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def transactions(self, request, pk=None):
        try:
            meter = Meter.objects.get(pk=pk, owner=request.user)
        except Meter.DoesNotExist:
            return Response({"error": "Meter not found"}, status=404)
        txs = meter.transactions.all().order_by("id")
        serializer = TransactionSerializer(txs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def audit_logs(self, request, pk=None):
        try:
            meter = Meter.objects.get(pk=pk, owner=request.user)
        except Meter.DoesNotExist:
            return Response({"error": "Meter not found"}, status=404)
        logs = TokenAuditLog.objects.filter(meter=meter)
        serializer = TokenAuditLogSerializer(logs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["post"])
    def apply_token(self, request, pk=None):
        token = request.data.get("token")
        if not token:
            return Response({"error": "Token is required"}, status=400)

        try:
            tx = Transaction.objects.get(token=token, meter__pk=pk, meter__owner=request.user)
        except Transaction.DoesNotExist:
            return Response({"error": "Invalid token or meter"}, status=404)

        if tx.is_applied:
            return Response({"message": "Token already applied"}, status=200)

        if tx.expiry_date and timezone.now() > tx.expiry_date:
            return Response({"error": "Token has expired"}, status=400)
        try:
            tx.apply_token()
        except Exception as e:
            return Response({"error": str(e)}, status=400)

        return Response(
            {
                "message": "Token applied successfully",
                "new_balance": tx.meter.credit_balance,
            }
        )
