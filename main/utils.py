from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode


def send_email_for_verify(request, user,is_password):
    current_site = get_current_site(request)
    context = {
        'user': user,
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': default_token_generator.make_token(user),
    }

    message = render_to_string('auth/change_password_letter.html' if is_password
                               else 'confirm_email_letter.html', context=context)
    email = EmailMessage(
        'Подтверждение',
        message,
        'email_verify@mail.ru',
        to=[user.email],
    )

    print(message)
    email.send()
