from django.db import models

class TheBoardMember(models.Model):
    screen_name = models.CharField(max_length=20, default='', primary_key=True)
    public_id = models.CharField(max_length=32, null=True)
    enclave_key = models.CharField(max_length=32, null=True)
    passphrase = models.CharField(max_length=20, default='')
    server_signing_key = models.TextField(max_length=2048, null=True)
    signing_key = models.TextField(max_length=2048, null=True)
    encryption_key = models.TextField(max_length=4096, null=True)
