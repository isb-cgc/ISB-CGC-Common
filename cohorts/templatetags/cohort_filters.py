from django.template.defaulttags import register
from django.contrib.auth.models import User
from cohorts.models import Cohort_Perms, Cohort


@register.filter
def cohort_owner_permission(list):
    return list.filter(perm=Cohort_Perms.OWNER)


@register.simple_tag
def public_cohort_count():
    idc_superuser = User.objects.get(username='idc')
    count = Cohort_Perms.objects.filter(user=idc_superuser,perm=Cohort_Perms.OWNER).distinct().count()
    return count


@register.filter
def get_displays(obj, joined, delimiter=None):
    if delimiter:
        return obj.get_displays(joined=joined, delimiter=delimiter)
    return obj.get_displays(joined=joined)


