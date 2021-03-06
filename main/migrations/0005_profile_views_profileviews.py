# Generated by Django 4.0.2 on 2022-03-12 16:11

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0004_remove_profile_tag_profile_tag'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='views',
            field=models.IntegerField(default=0, verbose_name='Количество просмотров'),
        ),
        migrations.CreateModel(
            name='ProfileViews',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=30)),
                ('profiles', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='views_list', to='main.profile')),
            ],
        ),
    ]
