# Generated by Django 3.1.5 on 2021-01-27 17:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='firstname',
            field=models.CharField(blank=True, db_index=True, max_length=255, null=True, unique=True),
        ),
        migrations.AddField(
            model_name='user',
            name='lastname',
            field=models.CharField(blank=True, db_index=True, max_length=255, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.EmailField(db_index=True, max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='username',
            field=models.CharField(blank=True, db_index=True, max_length=255, null=True, unique=True),
        ),
    ]