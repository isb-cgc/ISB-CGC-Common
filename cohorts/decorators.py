###
# Copyright 2015-2021, Institute for Systems Biology
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
        logger.info("[STATUS] Called api_auth decorator.")
        try:
            auth_header = request.META.get(settings.API_AUTH_HEADER, None)
            if not auth_header:
                logger.error("No Authorization header '{}' found for API call!".format(settings.API_AUTH_HEADER))
                return JsonResponse({
                        'message': 'No API authorization header - please be sure to provide the appropriate header and'
                        + ' API token for API calls.'
                }, status=403)

            auth_header = auth_header.split()

            # Make sure our Auth Header is the expected size
            if len(auth_header) == 1 or len(auth_header) > 2:
                logger.error("Malformed Authorization header: {}".format(auth_header))
                return JsonResponse({'message': 'Received malformed API authorization header.'}, status=403)

            # Check for our Auth Header Token key
            if auth_header[0].lower() != settings.API_AUTH_KEY.lower():
                logger.error("Invalid API Token key; received: {} - expected {}".format(
                    auth_header[0].lower(), settings.API_AUTH_KEY.lower()))
                return JsonResponse({'message': 'API Auth token key not recognized.'}, status=403)

            # Now actually validate with the token
            token = auth_header[1]
            Token.objects.select_related('user').get(key=token)

            # If a user was found, we've received a valid API call, and can proceed.
            return function(request, *args, **kwargs)

        except (ObjectDoesNotExist, UnicodeError):
            return JsonResponse({'message': 'Invalid API auth token supplied.'}, status=403)
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__

    return wrap