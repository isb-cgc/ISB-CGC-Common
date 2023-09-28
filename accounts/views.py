#
# Copyright 2015-2019, Institute for Systems Biology
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
#
from __future__ import absolute_import

from builtins import str
import logging

from allauth.account import views as account_views
from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views.decorators.csrf import csrf_protect
from google_helpers.stackdriver import StackDriverLogger
from google_helpers.bigquery.service import get_bigquery_service
from google_helpers.storage_service import get_storage_resource
from google_helpers.bigquery.bq_support import BigQuerySupport
from googleapiclient.errors import HttpError
from django.contrib.auth.models import User
from .models import *
from django.utils.html import escape
from .sa_utils import controlled_auth_datasets, have_linked_user

from .dcf_support import service_account_info_from_dcf_for_project, unregister_sa, TokenFailure, \
                        InternalTokenError, RefreshTokenExpired, DCFCommFailure

from json import loads as json_loads

logger = logging.getLogger('main_logger')

SERVICE_ACCOUNT_LOG_NAME = settings.SERVICE_ACCOUNT_LOG_NAME
GCP_REG_LOG_NAME = settings.GCP_ACTIVITY_LOG_NAME
SERVICE_ACCOUNT_BLACKLIST_PATH = settings.SERVICE_ACCOUNT_BLACKLIST_PATH
GOOGLE_ORG_WHITELIST_PATH = settings.GOOGLE_ORG_WHITELIST_PATH
MANAGED_SERVICE_ACCOUNTS_PATH = settings.MANAGED_SERVICE_ACCOUNTS_PATH

@login_required
def extended_logout_view(request):
    response = None

    try:
        response = account_views.logout(request)
    except Exception as e:
        logger.error("[ERROR] While attempting to log out:")
        logger.exception(e)
        messages.error(request, "There was an error while attempting to log out - please contact feedback@isb-cgc.org.")
        return redirect(reverse('user_detail', args=[request.user.id]))

    return response
