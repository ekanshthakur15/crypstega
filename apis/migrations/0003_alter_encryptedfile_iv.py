# Generated by Django 4.2.7 on 2023-12-07 05:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("apis", "0002_encryptedfile_iv"),
    ]

    operations = [
        migrations.AlterField(
            model_name="encryptedfile",
            name="iv",
            field=models.BinaryField(
                default=b"\r\x7fn\x9a\x9ee\x97\xe60\xd7Gp\xcc\xcd\xe01"
            ),
        ),
    ]
