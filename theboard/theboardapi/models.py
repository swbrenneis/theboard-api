from django.db import models

class TheBoardMember(models.Model):
    screen_name = models.CharField(max_length=20)
    public_id = models.CharField(max_length=32)
    enclave_key = models.CharField(max_length=32)
    signing_key = models.TextField()
    encryption_key = models.TextField()
