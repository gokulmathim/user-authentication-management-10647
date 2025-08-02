import os
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from django.contrib.auth import login, logout
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.conf import settings
from .serializers import (
    RegistrationSerializer, LoginSerializer,
    SessionSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer
)
from .utils import send_password_reset_email

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

@api_view(['GET'])
@permission_classes([AllowAny])
def health(request):
    return Response({"message": "Server is up!"})


# PUBLIC_INTERFACE
@swagger_auto_schema(
    method="post",
    operation_summary="Register new user",
    operation_description="Registers a new user with username, email, and password.",
    request_body=RegistrationSerializer,
    responses={201: openapi.Response("Created", RegistrationSerializer)}
)
@api_view(["POST"])
@permission_classes([AllowAny])
def register(request):
    """
    Registers a new user via POST /register/.
    Expects: username, email, password, password2 (all required)
    Returns: user information on success.
    """
    serializer = RegistrationSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# PUBLIC_INTERFACE
@swagger_auto_schema(
    method="post",
    operation_summary="Login",
    operation_description="Login with username and password to obtain an authenticated session.",
    request_body=LoginSerializer,
    responses={200: openapi.Response("OK"), 400: "Bad credentials"}
)
@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    """
    Logs in a user via session on POST /login/.
    Expects: username, password (as POST)
    Returns: session-based authenticated user details on success.
    """
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        login(request, serializer.validated_data['user'])
        session_serializer = SessionSerializer(serializer.validated_data['user'])
        return Response(session_serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# PUBLIC_INTERFACE
@swagger_auto_schema(
    method="post",
    operation_summary="Logout",
    operation_description="Logs out the authenticated user and removes their session.",
    responses={200: openapi.Response("OK")}
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """
    Logs out the current user (requires authentication).
    POST /logout/.
    """
    logout(request)
    return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)


# PUBLIC_INTERFACE
@swagger_auto_schema(
    method="get",
    operation_summary="Get Session",
    operation_description="Returns the currently authenticated user's session details.",
    responses={200: openapi.Response("OK", SessionSerializer)}
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def session_view(request):
    """
    Returns the currently authenticated user's session details as JSON.
    GET /session/
    """
    serializer = SessionSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)


# PUBLIC_INTERFACE
@swagger_auto_schema(
    method="post",
    operation_summary="Password Reset",
    operation_description="Sends an email with a reset link if the email is registered.",
    request_body=PasswordResetSerializer,
    responses={200: "Reset email sent"}
)
@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset(request):
    """
    Begins a password reset process.
    Expects: email
    POST /reset-password/
    Always returns 200 to avoid user enumeration.
    """
    serializer = PasswordResetSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            site_url = getattr(settings, "FRONTEND_URL", None) or os.getenv("FRONTEND_URL") or "http://localhost:3000"
            reset_url = f"{site_url}/reset-password-confirm/{uid}/{token}/"
            send_password_reset_email(user.email, reset_url)
        except User.DoesNotExist:
            pass  # Ignore to prevent user/email enumeration
        return Response({"detail": "If your email is registered, a reset link has been sent."}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# PUBLIC_INTERFACE
@swagger_auto_schema(
    method="post",
    operation_summary="Password Reset Confirm",
    operation_description="Resets the password when given a valid uid and token.",
    request_body=PasswordResetConfirmSerializer,
    responses={200: "Password has been reset"}
)
@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_confirm(request):
    """
    Completes a password reset given a valid uid/token and new password.
    Expects: uid, token, new_password
    POST /reset-password-confirm/
    """
    serializer = PasswordResetConfirmSerializer(data=request.data)
    if serializer.is_valid():
        try:
            uid = force_str(urlsafe_base64_decode(serializer.validated_data["uid"]))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"detail": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)
        token = serializer.validated_data["token"]
        if not default_token_generator.check_token(user, token):
            return Response({"detail": "Invalid or expired reset token."}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(serializer.validated_data["new_password"])
        user.save()
        return Response({"detail": "Password has been reset."}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
