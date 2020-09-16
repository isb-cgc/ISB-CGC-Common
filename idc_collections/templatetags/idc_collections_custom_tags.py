from django.template.defaulttags import register
from idc_collections.models import Program, ImagingDataCommonsVersion
import string

@register.simple_tag
def public_program_count():
    return Program.objects.filter(active=True, is_public=True).count()

@register.simple_tag(takes_context=True)
def user_program_count(context):
    user = context['user']

    userPrograms = user.program_set.filter(active=True)
    sharedPrograms = Program.objects.filter(shared__matched_user=user, shared__active=True, active=True)
    programs = userPrograms | sharedPrograms

    return programs.distinct().count()

@register.filter
def get_idc_version(reasons):
    return ImagingDataCommonsVersion.objects.get(active=True)
