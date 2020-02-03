import ipaddress
import logging
from django.http import HttpResponse
from django.conf import settings

logger = logging.getLogger("main_logger")


def api_only(view_func):
    def authorize(request, *args, **kwargs):
        logger.debug("Request host: {}".format(request.get_host()))
        logger.debug("Request IP: {}".format(request.get_host(request.META['REMOTE_ADDR'])))
        if request.get_host() == settings.API_HOST or ipaddress.ip_address(request.META['REMOTE_ADDR']).is_private:
            return view_func(request, *args, **kwargs)
        return HttpResponse('Access denied', status=403)
    return authorize
