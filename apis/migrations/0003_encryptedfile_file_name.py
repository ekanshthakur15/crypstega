# Generated by Django 4.2.5 on 2023-10-02 09:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("apis", "0002_encryptedfile_encryptionkey_steganographyimage_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="encryptedfile",
            name="file_name",
            field=models.CharField(default="file", max_length=25),
        ),
    ]
