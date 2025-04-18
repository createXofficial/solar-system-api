from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .models import Meter, Transaction, Complaint, Bill
from .serializers import MeterSerializer, TransactionSerializer, ComplaintSerializer, BillSerializer
from .permissions import IsCustomerOwner

class MeterViewSet(viewsets.ModelViewSet):
    serializer_class = MeterSerializer
    permission_classes = [IsAuthenticated, IsCustomerOwner]
    def get_queryset(self):
        if self.request.user.role == 'admin':
            return Meter.objects.all()
        return Meter.objects.filter(owner=self.request.user)

class TransactionViewSet(viewsets.ModelViewSet):
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ['meter__meter_number', 'created_at']
    search_fields = ['token']
    ordering_fields = ['created_at', 'amount']
    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin':
            return Transaction.objects.all()
        return Transaction.objects.filter(meter__owner=user)

class ComplaintViewSet(viewsets.ModelViewSet):
    serializer_class = ComplaintSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin':
            return Complaint.objects.all()
        return Complaint.objects.filter(customer=user)

class BillViewSet(viewsets.ModelViewSet):
    serializer_class = BillSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ['status']
    search_fields = ['meter__meter_number']
    ordering_fields = ['due_date']
    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin':
            return Bill.objects.all()
        return Bill.objects.filter(meter__owner=user)