from Crypto.Random import get_random_bytes
from django.contrib.auth.models import User
from django.db import models


class EncryptedFile(models.Model):

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='sent_files')
    recepient = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='received_files', default= 1)
    file_name = models.CharField(max_length=125, default="file")
    file = models.FileField(upload_to='files')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    iv = models.BinaryField(default= get_random_bytes(16))

    def __str__(self) -> str:
        return self.file_name

    class Meta:

        db_table = 'apis_encryptedfile'
