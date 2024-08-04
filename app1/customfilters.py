
from django import template
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

register = template.Library()

@register.filter
def custom_urlsafe_base64_encode(value):
    return urlsafe_base64_encode(force_bytes(value))

