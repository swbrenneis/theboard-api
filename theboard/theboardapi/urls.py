from django.urls import path
from .views import register

urlpatterns = [
    path('register/<str:screen_name>', register, name='register'),

]