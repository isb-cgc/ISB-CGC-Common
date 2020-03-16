###
# Copyright 2015-2020, Institute for Systems Biology
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

from django.core.exceptions import PermissionDenied
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse

import logging
logger = logging.getLogger('main_logger')

# Adapted from the Django REST Framework's TokenAuthentization class
# https://github.com/encode/django-rest-framework/blob/master/rest_framework/authentication.py
def api_auth(function):
    def wrap(request, *args, **kwargs):
        try:
            auth_header = request.META.get('HTTP_AUTHORIZATION',b'')
            # Force local dev to behave like deployed system
            if settings.DEBUG:
                auth_header = auth_header.encode('iso-8859-1')
            auth_header = auth_header.split()

            # Check for our Auth Header Token key, whatever that is.
            if not auth_header or auth_header[0].lower() != settings.API_AUTH_KEY.lower().encode():
                return JsonResponse({'message':'API access token not provided, or the wrong key was used.'},status=403)

            # Make sure our Auth Header is the expected size
            if len(auth_header) == 1 or len(auth_header) > 2:
                return JsonResponse({'message': 'API access token not provided, or the wrong key was used.'},status=403)

            # Now actually validate with the token
            token = auth_header[1].decode()
            Token.objects.select_related('user').get(key=token)

            # If a user was found, we've received a valid API call, and can proceed.
            return function(request, *args, **kwargs)

        except (ObjectDoesNotExist, UnicodeError):
            return JsonResponse({'message': 'Invalid API auth token supplied.'}, status=403)
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__

    return wrap