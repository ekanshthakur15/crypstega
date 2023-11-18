from cryptography.fernet import Fernet
from django.contrib.auth.models import User
from django.db import models


class EncryptedFile(models.Model):

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=125, default="file")
    file = models.FileField(upload_to='files')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.file_name

    class Meta:
        managed = False
        db_table = 'apis_encryptedfile'
