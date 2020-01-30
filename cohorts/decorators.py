import ipaddress
from django.http import HttpResponse
from django.conf import settings


def api_only(view_func):
    def authorize(request, *args, **kwargs):
        if request.get_host() == settings.API_HOST and ipaddress.ip_address(request.META['REMOTE_ADDR']).is_private:
            return view_func(request, *args, **kwargs)
        return HttpResponse('Access denied', status=403)
    return authorize
