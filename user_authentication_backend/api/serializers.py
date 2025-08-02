from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import update_last_login
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

User = get_user_model()


# PUBLIC_INTERFACE
class RegistrationSerializer(serializers.ModelSerializer):
    """Serializer for registering a new user."""
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password", "password2")
        extra_kwargs = {"email": {"required": True}}

    # PUBLIC_INTERFACE
    def validate(self, attrs):
        """Ensure passwords match during registration."""
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password": _("Password fields didn't match.")})
        return attrs

    # PUBLIC_INTERFACE
    def create(self, validated_data):
        """Create a new user instance with validated registration data."""
        validated_data.pop("password2")
        user = User.objects.create_user(username=validated_data["username"], email=validated_data["email"], password=validated_data["password"])
        user.is_active = True
        user.save()
        return user


# PUBLIC_INTERFACE
class LoginSerializer(serializers.Serializer):
    """Serializer for logging in a user."""
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    # PUBLIC_INTERFACE
    def validate(self, attrs):
        user = authenticate(username=attrs['username'], password=attrs['password'])
        if not user:
            raise serializers.ValidationError(_("Invalid credentials."))
        if not user.is_active:
            raise serializers.ValidationError(_("User account disabled."))
        update_last_login(None, user)
        attrs['user'] = user
        return attrs


# PUBLIC_INTERFACE
class SessionSerializer(serializers.ModelSerializer):
    """Serializer for current session user details."""
    class Meta:
        model = User
        fields = ("id", "username", "email", "is_active")


# PUBLIC_INTERFACE
class PasswordResetSerializer(serializers.Serializer):
    """Serializer for resetting user password."""
    email = serializers.EmailField(required=True)


# PUBLIC_INTERFACE
class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for confirming a reset with new password."""
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, validators=[validate_password])

    # PUBLIC_INTERFACE
    def validate(self, attrs):
        # Actual confirmation handled in the view
        return attrs
