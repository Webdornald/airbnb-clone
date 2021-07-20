# Generated by Django 3.2.5 on 2021-07-20 17:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0006_alter_user_email_secret'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='login_method',
            field=models.CharField(choices=[('eamil', 'Email'), ('github', 'Github'), ('kakao', 'Kako')], default='eamil', max_length=50),
        ),
    ]