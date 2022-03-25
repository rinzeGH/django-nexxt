from main.models import Profile
from django import template

register = template.Library()


@register.inclusion_tag('tags/navbar.html')
def navbar_user_buttons(request, user=None, profile=None):
    context = {'is_profile': False}
    context['user'] = user
    context['profile'] = profile
    if profile is None:
        if user is None:
            user = request.user
            context['is_user'] = user.is_authenticated
            context['user'] = user
            try:
                profile = Profile.objects.get(user=user)
                context['profile'] = profile
                context['is_profile'] = True
            except:
                pass
        else:
            context['is_user'] = user.is_authenticated
            try:
                profile = Profile.objects.get(user=user)
                context['profile'] = profile
                context['is_profile'] = True
            except:
                pass
    else:
        context['is_profile'] = True
        context['is_user'] = True
    return context
