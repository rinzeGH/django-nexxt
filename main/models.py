from django.contrib.auth.models import AbstractUser
from django.db import models
from django.urls import reverse


class User(AbstractUser):
    email = models.EmailField(verbose_name='эл. почта', unique=True)
    username = models.CharField(verbose_name='имя пользователя', max_length=30, unique=True)
    password = models.CharField(verbose_name='пароль', max_length=150)
    email_verify = models.BooleanField(default=False)
    user_permissions = 'real_user'
    groups = 'real_groups'


class Profile(models.Model):
    first_name = models.CharField(max_length=30, verbose_name='Имя')
    last_name = models.CharField(max_length=30, verbose_name='Фамилия')
    description = models.TextField(max_length=400, verbose_name='Описание')
    photo = models.ImageField(max_length=100, upload_to='photo/%Y/%m/%d/', verbose_name='Фото')
    views = models.IntegerField(default=0,verbose_name='Количество просмотров')
    vk_url = models.CharField('Ссылка ВК',default=None, max_length=50,blank=True)

    user = models.OneToOneField(User, related_name='profile', on_delete=models.CASCADE)
    gender = models.ForeignKey('Gender', related_name='profile', on_delete=models.PROTECT, verbose_name='Пол')
    status = models.ForeignKey('Status', related_name='profile', on_delete=models.PROTECT, verbose_name='Статус')
    grade = models.ForeignKey('Grade', related_name='profile', on_delete=models.PROTECT, verbose_name='Курс')
    faculty = models.ForeignKey('Faculty', related_name='profile', on_delete=models.PROTECT, verbose_name='Факультет')
    tag = models.ManyToManyField('Tag', related_name='profile', blank=True, null=True)

    slug = models.SlugField(max_length=30, unique=True, verbose_name='индивидуальный URL')

    class Meta:
        verbose_name = 'Профиль пользователя'
        verbose_name_plural = 'Профили пользователей'

    def get_absolute_url(self):
        return reverse('profile', kwargs={'prof_slug': self.slug})

    def __str__(self):
        return self.slug

class ProfileViews(models.Model):
    username = models.CharField(max_length=30)
    profiles = models.ForeignKey(Profile, on_delete=models.PROTECT,related_name='views_list')


class Gender(models.Model):
    name = models.CharField(max_length=10)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Гендер'
        verbose_name_plural = 'Гендеры'
        ordering = ['name', ]


class Status(models.Model):
    name = models.CharField(max_length=30, db_index=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Статус'
        verbose_name_plural = 'Статусы'
        ordering = ['name', ]


class Grade(models.Model):
    name = models.CharField(max_length=2, db_index=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Курс'
        verbose_name_plural = 'Курсы'
        ordering = ['name', ]


class Faculty(models.Model):
    name = models.CharField(max_length=10, db_index=True, verbose_name='Название')

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Факультет'
        verbose_name_plural = 'Факультеты'
        ordering = ['name', ]


class Tag(models.Model):
    name = models.CharField(max_length=50, unique=True, verbose_name='Название')

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Тег'
        verbose_name_plural = 'Теги'
