# Generated by Django 4.2.7 on 2023-12-07 05:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("apis", "0003_alter_encryptedfile_iv"),
    ]

    operations = [
        migrations.AlterField(
            model_name="encryptedfile",
            name="iv",
            field=models.BinaryField(
                default=b"J\xe8{\xf8\x19\x07\xd2O\xd9aD\xdfX\x91\xf8\xa2"
            ),
        ),
    ]
