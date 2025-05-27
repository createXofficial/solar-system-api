import logging

from django.db import transaction as db_transaction
from django.db.models import F, Min, Q, Sum
from django.utils import timezone

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, permissions, status, views, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from core.utils import get_changes, log_action

from .models import AuditLog, Bill, Complaint, Meter, TokenAuditLog, Transaction, User
from .permissions import IsAdminUser, IsCustomerOwner
from .serializers import (
    ApplyTokenSerializer,
    AuditLogSerializer,
    BillSerializer,
    ComplaintSerializer,
    DebtorSummarySerializer,
    MeterSerializer,
    TokenAuditLogSerializer,
    TransactionSerializer,
)

logger = logging.getLogger(__name__)


class ApplyTokenView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ApplyTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]

        with db_transaction.atomic():
            try:
                transaction = Transaction.objects.select_related("meter").get(token=token)
            except Transaction.DoesNotExist:
                return Response(
                    {
                        "ResponseCode": "111",
                        "ResponseMessage": "Transaction not found",
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

            if transaction.is_applied:
                logger.info(
                    f"User {self.request.user.get_short_name()} tried to apply token {token} but it was already applied"
                )
                return Response(
                    {
                        "ResponseCode": "111",
                        "ResponseMessage": "Token already applied",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if transaction.expiry_date and timezone.now() > transaction.expiry_date:
                logger.info(
                    f"User {self.request.user.get_short_name()} tried to apply token {token} but it was expired"
                )
                return Response(
                    {
                        "ResponseCode": "111",
                        "ResponseMessage": "Token has expired",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Track changes and apply token
            old_data = {
                "is_applied": transaction.is_applied,
                "meter_credit": transaction.meter.credit_balance,
            }

            transaction.apply_token()

            new_data = {
                "is_applied": transaction.is_applied,
                "meter_credit": transaction.meter.credit_balance,
            }

            changes = get_changes(old_data, new_data)

            # Log to audit trail
            log_action(
                user=self.request.user,
                model_name="Transaction",
                action="updated",
                description=f"Applied token {token}",
                metadata={"token": token, "changes": changes},
            )

            logger.info(f"User {self.request.user.get_full_name()} applied token: {token}")

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
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["owner"]
    search_fields = ["meter_number", "owner__email"]

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated or not hasattr(user, "role"):
            raise PermissionDenied("Authentication required or role missing.")

        queryset = Meter.objects.all().order_by("id")
        # owner_id = self.request.query_params.get("owner")
        if user.role == "admin":
            return queryset

        return queryset.filter(owner=user)

    def perform_create(self, serializer):
        instance = serializer.save()
        log_action(
            user=self.request.user,
            model_name="Meter",
            action="created",
            description=f"Created meter {instance.meter_number}",
        )

    def perform_update(self, serializer):
        old_instance = self.get_object()
        old_data = {
            field.name: getattr(old_instance, field.name) for field in old_instance._meta.fields
        }

        instance = serializer.save()

        new_data = {field.name: getattr(instance, field.name) for field in instance._meta.fields}
        changes = get_changes(old_instance, new_data)

        log_action(
            user=self.request.user,
            model_name="Meter",
            action="updated",
            description=f"Updated meter {instance.meter_number}",
            metadata=changes,

        )
    def perform_destroy(self, instance):
        meter_number = instance.meter_number
        instance.delete()
        log_action(
            user=self.request.user,
            model_name="Meter",
            action="deleted",
            description=f"Deleted meter {meter_number}",
        )


class TransactionViewSet(viewsets.ModelViewSet):
    queryset = Transaction.objects.select_related("meter", "meter__owner").all().order_by("id")
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["meter__owner", "is_applied"]
    search_fields = ["meter__meter_number", "token"]
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        instance = serializer.save()
        log_action(
            user=self.request.user,
            model_name="Transaction",
            action="created",
            description=f"Created transaction {instance.id} for meter {instance.meter.meter_number}",
        )

    def perform_update(self, serializer):
        old_instance = self.get_object()
        old_data = {
            field.name: getattr(old_instance, field.name) for field in old_instance._meta.fields
        }

        instance = serializer.save()

        new_data = {field.name: getattr(instance, field.name) for field in instance._meta.fields}
        changes = get_changes(old_instance, new_data)

        log_action(
            user=self.request.user,
            model_name="Transaction",
            action="updated",
            description=f"Updated transaction {instance.id} for meter {instance.meter.meter_number}",
            metadata=changes,
        )

    def perform_destroy(self, instance):
        transaction_id = instance.id
        meter_number = instance.meter.meter_number
        instance.delete()
        log_action(
            user=self.request.user,
            model_name="Transaction",
            action="deleted",
            description=f"Deleted transaction {transaction_id} for meter {meter_number}",
        )

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def apply(self, request, pk=None):
        try:
            transaction = self.get_object()
            if transaction.is_applied:
                return Response(
                    {"message": "Token already applied."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            transaction.apply_token()
            log_action(
                user=self.request.user,
                model_name="Transaction",
                action="updated",
                description=f"Applied token for transaction {transaction.id} on meter {transaction.meter.meter_number}",
            )
            return Response(
                {
                    "ResponseCode": "000",
                    "ResponseMessage": "Token applied successfully.",
                }
            )

        except Exception as e:
            log_action(
                user=self.request.user,
                model_name="Transaction",
                action="updated",
                description=f"Error applying token for transaction {pk}: {str(e)}",
                status=False,
            )
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class DebtorsViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        if request.user.role != "admin":
            return Response(
                {
                    "responseCode": "111",
                    "responseMessage": "You do not have permission to view this data.",
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        customers = User.objects.filter(role="customer")
        debtors = []

        for customer in customers:
            unpaid_bills = Bill.objects.filter(
                meter__owner=customer, status="pending"
            ).select_related("meter")
            if unpaid_bills.exists():
                meter = unpaid_bills.first().meter

                amount_owing = unpaid_bills.aggregate(total_due=Sum("amount_due"))["total_due"] or 0

                earliest_due = unpaid_bills.aggregate(next_due=Min("due_date"))["next_due"]

                # Get unique meters related to unpaid bills
                meters = []
                seen_meter_ids = set()
                for bill in unpaid_bills:
                    meter = bill.meter
                    if meter.id not in seen_meter_ids:
                        seen_meter_ids.add(meter.id)
                        meters.append(
                            {
                                "meter_number": meter.meter_number,
                                "location": meter.location,
                                "status": meter.status,
                            }
                        )

                debtors.append(
                    {
                        "full_name": f"{customer.first_name} {customer.last_name}".strip(),
                        "meter": meter,
                        "email": customer.email,
                        "phone": customer.phone,
                        "gender": customer.gender,
                        "total_owing": amount_owing,
                        "due_date": earliest_due,
                    }
                )

        serializer = DebtorSummarySerializer(debtors, many=True)
        return Response(
            {
                "responseCode": "000",
                "responseMessage": "Debtors retrieved successfully.",
                "data": serializer.data,
            }
        )


class TokenAuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = TokenAuditLog.objects.all().order_by("id")
    serializer_class = TokenAuditLogSerializer
    permission_classes = [IsAuthenticated]


import logging

from rest_framework.exceptions import PermissionDenied

from core.utils import get_changes, log_action

logger = logging.getLogger(__name__)


class ComplaintViewSet(viewsets.ModelViewSet):
    serializer_class = ComplaintSerializer
    permission_classes = [IsAuthenticated]

    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["customer", "technician", "status"]


    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated or not hasattr(user, "role"):
            raise PermissionDenied("Authentication required or role missing.")

        queryset = Complaint.objects.select_related("customer", "technician").all().order_by("id")
        if user.role == "admin":
            return queryset
        return queryset.filter(customer=user)

    def perform_create(self, serializer):
        instance = serializer.save()
        log_action(
            user=self.request.user,
            model_name="Complaint",
            action="created",
            description=f"Created complaint {instance.id} by user {self.request.user.first_name}",
        )

    def perform_update(self, serializer):
        old_instance = self.get_object()
        old_data = {
            field.name: getattr(old_instance, field.name) for field in old_instance._meta.fields
        }
        instance = serializer.save()
        new_data = {field.name: getattr(instance, field.name) for field in instance._meta.fields}
        changes = get_changes(old_data, new_data)

        log_action(
            user=self.request.user,
            model_name="Complaint",
            action="updated",
            description=f"Updated complaint {instance.id}",
            metadata=changes,
        )

    def perform_destroy(self, instance):
        complaint_id = instance.id
        instance.delete()
        log_action(
            user=self.request.user,
            model_name="Complaint",
            action="deleted",
            description=f"Deleted complaint {complaint_id}",
        )

    @action(detail=True, methods=["post"])
    def assign_technician(self, request, pk=None):
        tech_id = request.data.get("technician_id")
        try:
            complaint = self.get_queryset().get(pk=pk)
            technician = User.objects.get(pk=tech_id, role="technician")

            old_technician = complaint.technician
            complaint.technician = technician
            complaint.save()

            change = get_changes(
                old_instance=old_technician,
                new_instance=technician,
            )

            logger.info(
                f"Technician {technician.get_full_name()} assigned to complaint({complaint}) by user {self.request.user.get_full_name()}"
            )

            log_action(
                user=request.user,
                model_name="Complaint",
                action="updated",
                description=f"Assigned technician {technician.get_full_name()} to complaint {complaint.id}",
                metadata=change,
            )

            return Response(
                {
                    "ResponseCode": "000",
                    "ResponseMessage": f"Assigned complaint to {technician.get_full_name()} successfully.",
                }
            )
        except Exception as e:
            logger.error(f"Error assigning technician to complaint {pk}: {str(e)}")
            log_action(
                user=self.request.user,
                model_name="Complaint",
                action="updated",
                description=f"Error assigning technician to complaint {pk} to {technician.get_full_name()}",
                status=False,
            )
            return Response(
                {
                    "ResponseCode": "111",
                    "ResponseMessage": f"Error assigning technician: {str(e)}",
                },
                status=400,
            )


class BillViewSet(viewsets.ModelViewSet):
    serializer_class = BillSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter, DjangoFilterBackend]
    filterset_fields = ["status", "meter__owner"]
    search_fields = ["meter__meter_number"]
    ordering_fields = ["due_date"]

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated or not hasattr(user, "role"):
            raise PermissionDenied("Authentication required or role missing.")

        queryset = Bill.objects.select_related("meter", "meter__owner").all().order_by("id")
        if user.role == "admin":
            return queryset
        return queryset.filter(meter__owner=user)

    def perform_create(self, serializer):
        instance = serializer.save()
        log_action(
            user=self.request.user,
            model_name="Bill",
            action="created",
            description=f"Created bill {instance.id} for meter {instance.meter.meter_number}",
        )

    def perform_update(self, serializer):
        old_instance = self.get_object()
        old_data = {
            field.name: getattr(old_instance, field.name) for field in old_instance._meta.fields
        }
        instance = serializer.save()
        new_data = {field.name: getattr(instance, field.name) for field in instance._meta.fields}
        changes = get_changes(old_data, new_data)

        log_action(
            user=self.request.user,
            model_name="Bill",
            action="updated",
            description=f"Updated bill {instance.id}",
            metadata=changes,
        )

    def perform_destroy(self, instance):
        bill_id = instance.id
        instance.delete()
        log_action(
            user=self.request.user,
            model_name="Bill",
            action="deleted",
            description=f"Deleted bill {bill_id}",
        )

class CustomerViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["get"])
    def meters(self, request):
        meters = Meter.objects.filter(owner=request.user)
        serializer = MeterSerializer(meters, many=True)
        return Response(
            {
                "ResponseCode": "000",
                "ResponseMessage": "Meters retrieved successfully.",
                "data": serializer.data,
            }
        )

    @action(detail=True, methods=["get"])
    def bills(self, request, pk=None):
        try:
            meter = Meter.objects.get(pk=pk, owner=request.user)
        except Meter.DoesNotExist:
            return Response({"error": "Meter not found"}, status=404)
        bills = meter.bills.all().order_by("id")
        serializer = BillSerializer(bills, many=True)
        return Response(
            {
                "ResponseCode": "000",
                "ResponseMessage": "Bills retrieved successfully.",
                "data": serializer.data,
            }
        )

    @action(detail=True, methods=["get"])
    def transactions(self, request, pk=None):
        try:
            meter = Meter.objects.get(pk=pk, owner=request.user)
        except Meter.DoesNotExist:
            return Response({"error": "Meter not found"}, status=404)
        txs = meter.transactions.all().order_by("id")
        serializer = TransactionSerializer(txs, many=True)
        return Response(
            {
                "ResponseCode": "000",
                "ResponseMessage": "Transactions retrieved successfully.",
                "data": serializer.data,
            }
        )

    @action(detail=True, methods=["get"])
    def audit_logs(self, request, pk=None):
        try:
            meter = Meter.objects.get(pk=pk, owner=request.user)
        except Meter.DoesNotExist:
            return Response({"error": "Meter not found"}, status=404)
        logs = TokenAuditLog.objects.filter(meter=meter)
        serializer = TokenAuditLogSerializer(logs, many=True)
        return Response(
            {
                "ResponseCode": "000",
                "ResponseMessage": "Token Audit logs retrieved successfully.",
                "data": serializer.data,
            }
        )

    @action(detail=True, methods=["get"])
    def complaints(self, request, pk=None):
        try:
            meter = Meter.objects.get(pk=pk, owner=request.user)
        except Meter.DoesNotExist:
            return Response({"error": "Meter not found"}, status=404)
        complaints = meter.complaints.all().order_by("id")
        serializer = ComplaintSerializer(complaints, many=True)
        return Response(
            {
                "ResponseCode": "000",
                "ResponseMessage": "Complaints retrieved successfully.",
                "data": serializer.data,
            }
        )


class IsAdminUserOrStaff(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and (request.user.is_staff or request.user.role == "admin")


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AuditLog.objects.all().order_by("-timestamp")
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdminUserOrStaff]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["model_name", "action", "user__email", "success"]
    search_fields = ["description", "user_snapshot", "model_name"]

    ordering_fields = ["timestamp"]
