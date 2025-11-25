from django.db import models

class TheBoardMember(models.Model):
    screen_name = models.CharField(max_length=20, default='', primary_key=True)
    public_id = models.CharField(max_length=512, null=True)
    enclave_key = models.CharField(max_length=512, null=True)
    passphrase = models.CharField(max_length=120, default='')
    server_signing_key = models.TextField(max_length=2048, null=True)
    signing_key = models.TextField(max_length=2048, null=True)
    encryption_key = models.TextField(max_length=4096, null=True)

class SessionContext(models.Model):
    screen_name = models.CharField(max_length=100, default='', primary_key=True)
    session_id = models.CharField(max_length=64, null=True)
    ephemeral_key = models.CharField(max_length=1024, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
