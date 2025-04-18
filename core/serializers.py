from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import Bill, Complaint, Meter, TokenAuditLog,Transaction, User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'role']
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class MeterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Meter
        fields = '__all__'

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = '__all__'

class ComplaintSerializer(serializers.ModelSerializer):
    class Meta:
        model = Complaint
        fields = '__all__'

class BillSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bill
        fields = '__all__'
        

class ApplyTokenSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate_token(self, value):
        try:
            transaction = Transaction.objects.get(token=value)
        except Transaction.DoesNotExist:
            raise serializers.ValidationError("Invalid token provided.")
        if transaction.is_applied:
            raise serializers.ValidationError("Token has already been applied.")
        return value
    

class TokenAuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = TokenAuditLog
        fields = '__all__'