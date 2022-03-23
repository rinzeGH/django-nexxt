from django.contrib import admin

from .models import *


class ProfileAdmin(admin.ModelAdmin):
    list_display = ('pk', 'first_name', 'slug', 'gender', 'grade', 'faculty','views')
    list_display_links = ('first_name', 'pk')
    search_fields = ('pk', 'first_name', 'slug', 'gender', 'grade', 'faculty')

class UserAdmin(admin.ModelAdmin):
    list_display = ('pk', 'username', 'email', 'email_verify')
    list_display_links = ('username', 'pk')
    search_fields = ('pk', 'username', 'email')

admin.site.register(Profile, ProfileAdmin)
admin.site.register(Status)
admin.site.register(Gender)
admin.site.register(Grade)
admin.site.register(Faculty)
admin.site.register(User, UserAdmin)
admin.site.register(Tag)





