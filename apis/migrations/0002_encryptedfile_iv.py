# Generated by Django 4.2.7 on 2023-12-06 22:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("apis", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="encryptedfile",
            name="iv",
            field=models.BinaryField(
                default=b"'(\x0b\xb9\x11\x0fV\x7fh\x10\xa2\xd7\xc3\xc1\xd1\xb4"
            ),
        ),
    ]
