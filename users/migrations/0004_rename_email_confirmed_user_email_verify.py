# Generated by Django 3.2.5 on 2021-07-19 23:38

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_user_email_secret'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='email_confirmed',
            new_name='email_verify',
        ),
    ]
