from django.urls import path
from .views import register, login, init

urlpatterns = [
    path('register/<str:screen_name>', register, name='register'),
    path('login', login, name='login'),
    path('init', init, name='init' ),   # Get the CSRF token
]