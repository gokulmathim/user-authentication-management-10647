from django.urls import path
from .views import (
    health, register, login_view, logout_view,
    session_view, password_reset, password_reset_confirm,
)

urlpatterns = [
    path('health/', health, name='Health'),
    path('register/', register, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('session/', session_view, name='session'),
    path('reset-password/', password_reset, name='reset-password'),
    path('reset-password-confirm/', password_reset_confirm, name='reset-password-confirm'),
]
