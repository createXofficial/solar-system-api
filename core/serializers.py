from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from rest_framework import serializers

from .models import AuditLog, Bill, Complaint, Meter, TokenAuditLog, Transaction, UserRole

User = get_user_model()


class TwoFactorCodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6)


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password])

    class Meta:
        model = User
        fields = ("username", "email", "password", "role")

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "A user with this email already exists.")
        return value

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError(
                "A user with this username already exists.")
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


class UserSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "telephone", "gender"]


class MeterSerializer(serializers.ModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    owner_details = UserSummarySerializer(source="owner", read_only=True)
    installed_by = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), required=False, allow_null=True
    )

    class Meta:
        model = Meter
        fields = [
            "id",
            "meter_number",
            "owner",  # for writing
            "owner_details",  # read-only nested
            "location",
            "status",
            "credit_balance",
            "date_installed",
            "installed_by",  # for writing
        ]

    def validate_owner(self, value):
        if value.role != UserRole.CUSTOMER:
            raise serializers.ValidationError(
                "Meter owner must be a customer.")
        return value

    def validate_installed_by(self, value):
        if value.role not in [UserRole.ADMIN, UserRole.TECHNICIAN]:
            raise serializers.ValidationError(
                "Installer must be an admin or technician.")
        return value


class TransactionSerializer(serializers.ModelSerializer):
    meter = MeterSerializer(read_only=True)  # For response display
    meter_id = serializers.PrimaryKeyRelatedField(
        queryset=Meter.objects.all(), write_only=True
    )  # For input

    class Meta:
        model = Transaction
        fields = "__all__"

    def validate(self, data):
        if data.get("token") and Transaction.objects.filter(token=data["token"]).exists():
            transaction = Transaction.objects.get(token=data["token"])
            if transaction.is_expired():
                raise serializers.ValidationError("This token has expired.")
        return data

    def create(self, validated_data):
        meter = validated_data.pop("meter_id")
        return Transaction.objects.create(meter=meter, **validated_data)


class ComplaintSerializer(serializers.ModelSerializer):
    class Meta:
        model = Complaint
        fields = "__all__"


class BillSerializer(serializers.ModelSerializer):
    meter = MeterSerializer(read_only=True)
    meter_id = serializers.PrimaryKeyRelatedField(
        queryset=Meter.objects.all(), source="meter", write_only=True
    )
    status_display = serializers.CharField(
        source="get_status_display", read_only=True)
    remaining_amount = serializers.SerializerMethodField()

    class Meta:
        model = Bill
        fields = "__all__"

    def get_remaining_amount(self, obj):
        return obj.amount_due

    def validate_meter(self, meter):
        request = self.context.get("request")
        if request and hasattr(request.user, "role") and request.user.role != "admin":
            if meter.owner != request.user:
                raise serializers.ValidationError(
                    "You cannot assign a bill to a meter you do not own."
                )
        return meter


class ApplyTokenSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate_token(self, value):
        try:
            transaction = Transaction.objects.get(token=value)
        except Transaction.DoesNotExist:
            raise serializers.ValidationError("Invalid token provided.")

        if transaction.is_applied:
            raise serializers.ValidationError(
                "Token has already been applied.")

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


class AuditLogSerializer(serializers.ModelSerializer):
    user_display = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = [
            "id",
            "user_display",
            "model_name",
            "action",
            "description",
            "timestamp",
        ]

    def get_user_display(self, obj):
        if obj.user and obj.user.is_active:
            return obj.user.username
        elif obj.user_snapshot:
            return f"{obj.user_snapshot} (Deleted)"
        return "Unknown"
