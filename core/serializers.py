from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from rest_framework import serializers

from .models import Bill, Complaint, Meter, TokenAuditLog, Transaction

User = get_user_model()


class TwoFactorCodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6)


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])

    class Meta:
        model = User
        fields = ("username", "email", "password", "role")

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("A user with this username already exists.")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            role=validated_data["role"],
        )
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "role",
            "dob",
            "address",
            "telephone",
            "gender",
        ]


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_new_password = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_new_password"]:
            raise serializers.ValidationError("New passwords don't match.")

        try:
            validate_password(attrs["new_password"])
        except ValidationError as e:
            raise serializers.ValidationError({"new_password": e.messages})
        return attrs


class MeterSerializer(serializers.ModelSerializer):
    owner = UserSerializer(read_only=True)
    installed_by = UserSerializer(read_only=True)

    class Meta:
        model = Meter
        fields = "__all__"


class TransactionSerializer(serializers.ModelSerializer):
    meter = MeterSerializer(read_only=True)

    class Meta:
        model = Transaction
        fields = "__all__"

    def validate(self, data):
        if data.get("token") and Transaction.objects.filter(token=data["token"]).exists():
            transaction = Transaction.objects.get(token=data["token"])
            if transaction.is_expired():
                raise serializers.ValidationError("This token has expired.")
        return data


class ComplaintSerializer(serializers.ModelSerializer):
    class Meta:
        model = Complaint
        fields = "__all__"


class BillSerializer(serializers.ModelSerializer):
    meter = MeterSerializer(read_only=True)
    status_display = serializers.CharField(source="get_status_display", read_only=True)
    remaining_amount = serializers.SerializerMethodField()

    class Meta:
        model = Bill
        fields = "__all__"

    def get_remaining_amount(self, obj):
        return obj.amount_due


class ApplyTokenSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate_token(self, value):
        try:
            transaction = Transaction.objects.get(token=value)
        except Transaction.DoesNotExist:
            raise serializers.ValidationError("Invalid token provided.")

        if transaction.is_applied:
            raise serializers.ValidationError("Token has already been applied.")

        if transaction.is_expired():
            raise serializers.ValidationError("This token has expired.")

        if transaction.meter.status not in ["active"]:
            raise serializers.ValidationError(
                "The meter is not in a valid state to apply the token."
            )

        return value


class TokenAuditLogSerializer(serializers.ModelSerializer):
    transaction = TransactionSerializer(read_only=True)
    meter = MeterSerializer(read_only=True)

    class Meta:
        model = TokenAuditLog
        fields = "__all__"


class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data["new_password"] != data["confirm_new_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        try:
            validate_password(data["new_password"])
        except ValidationError as e:
            raise serializers.ValidationError({"new_password": e.messages})
        return data
