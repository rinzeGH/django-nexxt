from django.contrib.auth import logout, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import LoginView
import requests
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.views import View
from django.views.generic import DetailView, CreateView, TemplateView, UpdateView
from .models import *
from .forms import *
from django.core.paginator import Paginator
from .utils import send_email_for_verify, vk_autentification
from rest_framework import generics
from rest_framework.views import APIView
from .serializers import UserApiViewSerial
from rest_framework.response import Response
from mysite import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.contrib.messages.views import SuccessMessageMixin


class Home(TemplateView, SuccessMessageMixin):
    template_name = 'home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        context['user'] = user
        try:
            context['profile'] = Profile.objects.get(user=user)
        except:
            context['profile'] = None
        return context


def Login(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            if user.email_verify:
                login(request, user)
                return redirect('home')
            else:
                send_email_for_verify(request, user, is_password=False)
                return render(request, 'auth/email_verify.html')

    form = LoginForm(request)
    return render(request, 'auth/login.html', {'form': form})


def Singup(request):
    if request.method == 'POST':
        form = SingupForm(request.POST)
        if form.is_valid():
            form.save()
            user = User.objects.get(username=form.cleaned_data['username'])
            send_email_for_verify(request, user, is_password=False)
            messages.add_message(request, messages.SUCCESS, 'Проверьте почту!')
            return render(request, 'auth/email_verify.html')
    else:
        form = SingupForm
    return render(request, 'auth/singup.html', {'form': form})


class ChangePassword(LoginRequiredMixin, View):
    def get(self, request):
        form = ChangePasswordForm
        return render(request, 'auth/changepassword.html', {'form': form})

    def post(self, request):
        form = ChangePasswordForm(request.POST)
        if form.is_valid():
            user = User.objects.get(email=form.cleaned_data['email'])
            send_email_for_verify(request, user, is_password=True)
            return render(request, 'auth/changepassword.html', {'form': form})


class EmailConfirm(View):
    def get(self, request, uid64, token):
        user = self.get_user(uid64)
        if user is not None and default_token_generator.check_token(user, token):
            user.email_verify = True
            user.save()
            login(request, user)
            return redirect('home')
        return redirect('invalid_verify_link')

    @staticmethod
    def get_user(uid64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uid64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationError):
            user = None
        return user


def invalid_verify_link(request):
    return render(request, 'auth/invalid_verify_link.html')


def Logout(request):
    logout(request)
    return redirect('home')


class ProfileView(LoginRequiredMixin, TemplateView):
    model = Profile
    template_name = 'profile/profile.html'


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        current_user = self.request.user
        context['user'] = current_user
        current_user_profile = Profile.objects.get(user=current_user)
        context['current_profile'] = current_user_profile
        profile = Profile.objects\
            .select_related('gender', 'status')\
            .prefetch_related('user')\
            .get(slug=self.kwargs['prof_slug'])
        context['profile'] = profile
        if current_user == profile.user:
            return context
        else:
            if (ProfileViews.objects.filter(username=current_user.username, profiles=profile)):
                return context
            else:
                ProfileViews.objects.create(username=current_user.username, profiles=profile)
                profile.views = profile.views + 1
                profile.save()
                return context


@login_required()
def Choose(request):
    user = request.user
    profiles = Profile.objects.prefetch_related('tag').exclude(user=user)
    paginator = Paginator(profiles, 15)
    if request.method == 'POST':
        form = FilterForm(request.POST)
        if form.is_valid():
            profiles = profiles.filter(gender=form.cleaned_data['gender'],
                                       status=form.cleaned_data['status'],
                                       grade=form.cleaned_data['grade'],
                                       faculty=form.cleaned_data['faculty'])
            profiles = profiles.filter(tag__in=form.cleaned_data['tag']).distinct()
            paginator = Paginator(profiles, 15)
    else:
        form = FilterForm
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    context = {
        'profiles': profiles,
        'form': form,
        'page_obj': page_obj,
        'user': user,
    }
    return render(request, 'choose.html', context)


class CreateProfile(LoginRequiredMixin, View):
    def post(self, request):
        user = request.user
        profile_form = ProfileForm(request.POST)
        if profile_form.is_valid():
            Profile.objects.update_or_create(user=user,
                                             defaults={**profile_form.cleaned_data})
            return redirect('home')

    def get(self, request):
        form = ProfileForm()
        context = {'form': form, 'flag': True, 'user': request.user}
        return render(request, 'profile/profcreate.html', context=context)


def VkAuth(request):
    # apiurl = f'https://login.vk.com/?act=openapi&oauth=1&aid={settings.SOCIAL_AUTH_VK_OAUTH2_KEY}&location=127.0.0.1&new=1&response_type=code'
    return redirect(f'https://oauth.vk.com/authorize?client_id={settings.SOCIAL_AUTH_VK_OAUTH2_KEY}' \
                    f'&display=page&redirect_uri={settings.SOCIAL_AUTH_VK_REDIRECT_URL}' \
                    f'&scope=notify&response_type=code&v=5.131')


def VkAuthConfirm(request):
    respones = vk_autentification(request)
    if 'error' in respones:
        return redirect('home')
    else:
        profile = Profile.objects.get(user=request.user)
        profile.vk_url = respones['user_id']
        profile.save()
        return redirect('profile', prof_slug=profile.slug)


@login_required()
def VkDelete(request):
    profile = Profile.objects.get(user=request.user)
    profile.vk_url = 'None'
    profile.save()
    return redirect('home')
