import string

from django.template.defaulttags import register
from projects.models import Program

@register.simple_tag
def public_program_count():
    return Program.objects.filter(active=True, is_public=True).count()

@register.simple_tag(takes_context=True)
def user_program_count(context):
    user = context['user']

    userPrograms = user.program_set.all().filter(active=True)
    sharedPrograms = Program.objects.filter(shared__matched_user=user, shared__active=True, active=True)
    programs = userPrograms | sharedPrograms

    return programs.distinct().count()
