# Generated by Django 4.2.5 on 2023-11-17 18:13

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("apis", "0011_rename_file_data_encryptedfile_file"),
    ]

    operations = [
        migrations.DeleteModel(
            name="SteganographyImage",
        ),
    ]
