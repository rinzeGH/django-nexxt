from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, UserChangeForm
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404

from .models import *
from django.core.validators import EmailValidator
from django.urls import reverse_lazy
import re

from .utils import send_email_for_verify


class SingupForm(UserCreationForm):
    username = forms.CharField(max_length=25, label='Логин')
    password1 = forms.CharField(label='Пароль')
    password2 = forms.CharField(label='Повтор пароля')
    email = forms.EmailField(label='эл.Почта')

    class Meta:
        model = User
        fields = ('username', 'password1', 'password2', 'email')
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'password1': forms.PasswordInput(attrs={'class': 'form-control', 'type': 'password'}),
            'password2': forms.PasswordInput(attrs={'class': 'form-control', 'type': 'password'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'})
        }

    def clean_email(self):
        email = self.cleaned_data['email']
        if not re.match(r'^[a-zA-Z0-9_.+-]+@study.utmn.ru', email):
            raise ValidationError('Вы регистрируетесь не на корп.почту ТюмГУ')
        return email


class LoginForm(AuthenticationForm):
    username = forms.CharField(max_length=30, widget=forms.TextInput())
    password = forms.CharField(max_length=30, widget=forms.PasswordInput())


class ChangePasswordForm(forms.Form):
    email = forms.EmailField(label='эл.Почта', widget=forms.EmailInput(attrs={'class': 'form-control'}))


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ('first_name', 'last_name', 'description', 'gender', 'status', 'slug', 'grade', 'faculty')


class FilterForm(forms.Form):
    gender = forms.ModelChoiceField(label='Пол', queryset=Gender.objects.all(), blank=True,
                                    widget=forms.Select(attrs={'class': 'form-control'}))
    status = forms.ModelChoiceField(label='Статус', queryset=Status.objects.all(), blank=True,
                                    widget=forms.Select(attrs={'class': 'form-control'}))
    grade = forms.ModelChoiceField(label='Курс', queryset=Grade.objects.all(), blank=True,
                                   widget=forms.Select(attrs={'class': 'form-control'}))
    faculty = forms.ModelChoiceField(label='Факультет', queryset=Faculty.objects.all(), blank=True,
                                     widget=forms.Select(attrs={'class': 'form-control'}))
    tag = forms.ModelMultipleChoiceField(label='Тэги', queryset=Tag.objects.all(),
                                     widget=forms.SelectMultiple(attrs={'class': 'form-control'}), blank=True)
