from django.contrib.auth.views import PasswordResetConfirmView, PasswordResetCompleteView
from django.urls import path, include
from .views import *


urlpatterns = [

    path('', Home.as_view(), name='home'),
    path('singup/', Singup, name='singup'),
    path('logout/', Logout, name='logout'),
    path('login/', Login, name='login'),
    path('confirm_email/<uid64>/<token>/', EmailConfirm.as_view(), name='confirm_email'),
    path('invalid_verify_link/', invalid_verify_link, name='invalid_verify_link'),

    path('user/<slug:prof_slug>', ProfileView.as_view(), name='profile'),
    path('createprofile/', CreateProfile.as_view(), name='createprofile'),
    path('editprofile/', CreateProfile.as_view(), name='editprofile'),

    path('choose/', Choose, name='choose'),

    path('change_password', ChangePassword.as_view(), name='changepassword'),
    path('confirm_password/<uidb64>/<token>/',
         PasswordResetConfirmView.as_view(template_name="password_reset_confirm.html"), name='confirm_password'),
    path('change_password/done', PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'),
         name='password_reset_complete'),

    path('auth/',include('rest_framework_social_oauth2.urls')),
    path('auth/vk', VkAuth,name='vk_auth'),
    path('auth/vk/confirm/',VkAuthConfirm, name ='vk_auth_cofirm' ),
    path('auth/vk/delete/', VkDelete, name='vkdelete')

]
