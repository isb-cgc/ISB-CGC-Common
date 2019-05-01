"""

Copyright 2017, Institute for Systems Biology

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

from builtins import object
from json import loads as json_loads
import logging
import datetime
import pytz
from re import compile as re_compile

from jsonschema import validate as schema_validate, ValidationError
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.contrib.auth.models import User
from django.conf import settings
from googleapiclient.errors import HttpError
from google_helpers.stackdriver import StackDriverLogger
from google_helpers.resourcemanager_service import get_special_crm_resource
from .dcf_support import TokenFailure, InternalTokenError, RefreshTokenExpired, DCFCommFailure
from .sa_utils import get_project_deleters, unregister_all_gcp_sa


from accounts.models import GoogleProject

logger = logging.getLogger('main_logger')

GCP_REG_LOG_NAME = settings.GCP_ACTIVITY_LOG_NAME
SERVICE_ACCOUNT_LOG_NAME = settings.SERVICE_ACCOUNT_LOG_NAME

class ServiceObjectBase(object):
    """
    Base class for loading settings from JSON-objects.
    """

    # Regular expression for parsing the bucket name and object name from a Google
    # Cloud Storage path.
    CLOUD_STORAGE_PATH_RE = re_compile('gs://([a-zA-Z0-9][\w\-.]*[a-zA-Z0-9])/(.*)')

    @classmethod
    def get_gcs_bucket_and_object_from_path(cls, gcs_path):
        """
        Parses the bucket name and object name from a Google Cloud Storage path.

        Args:
            gcs_path: Google Cloud Storage path.

        Returns:
            (Bucket name, object name) tuple if path is valid, otherwise (None, None).

        """
        gcs_result = cls.CLOUD_STORAGE_PATH_RE.findall(gcs_path)

        if len(gcs_result) > 0:
            bucket_name, object_name = gcs_result[0]
            return bucket_name, object_name
        else:
            return None, None

    @classmethod
    def from_json_string(cls, json_string):
        json_data = json_loads(json_string)
        return cls.from_dict(json_data)

    @classmethod
    def load_file_contents(cls, local_file_path):
        with open(local_file_path, 'r') as fd:
            contents = fd.read()

        return contents

    @classmethod
    def from_local_json_file(cls, json_file_path):
        """
        Factory method for building a configuration class instance from a JSON file in the local file system.
        """
        logger.debug("{}.from_local_json_file {}".format(type(cls), repr(json_file_path)))
        file_contents = cls.load_file_contents(json_file_path)

        return cls.from_json_string(file_contents)

    @classmethod
    def from_google_cloud_storage(cls, bucket_name, filename):
        """
        Factory method for building a configuration class instance from a JSON file in the Google Cloud Storage.

        Args:
            bucket_name: bucket name.
            filename:    object name.

        Returns:
            File contents.
        """
        from google_helpers.storage_service import get_storage_resource
        logger.debug("{}.from_google_cloud_storage {} {}".format(type(cls), repr(bucket_name), repr(filename)))
        storage_service = get_storage_resource()
        req = storage_service.objects().get_media(bucket=bucket_name,
                                                  object=filename)
        json_file = req.execute()
        return cls.from_json_string(json_file)

    @classmethod
    def from_json_file_path(cls, config_file_path):
        """
        Factory method for building a configuration class instance from a JSON file. The JSON file can be either
        in the local file system or Google Cloud Storage.

        Delegates to method based the JSON file path. GCS path recognition is based naming guidelines document:
        https://cloud.google.com/storage/docs/naming

        Args:
            config_file_path: Path to a configuration JSON file.

        Returns:
            Configuration class instance.
        """
        bucket_name, object_name = cls.get_gcs_bucket_and_object_from_path(config_file_path)
        if bucket_name is not None and object_name is not None:
            return cls.from_google_cloud_storage(bucket_name, object_name)
        else:
            return cls.from_local_json_file(config_file_path)


# Object for confirming that a given service account is a google system managed service account
class ManagedServiceAccounts(ServiceObjectBase):
    SCHEMA = {
        'type': 'object',
        'properties': {
            'managed_service_accounts': {
                'type': 'array',
                'items': {
                    'type': 'string'
                }
            }
        },
        'required': [
            'managed_service_accounts'
        ]
    }

    def __init__(self, managed_service_accounts):
        self.managed_service_accounts = set(managed_service_accounts)

    def is_managed(self, service_account):
        return '@{}'.format(service_account.split('@')[-1]) in self.managed_service_accounts

    def is_managed_this_project(self, service_account, projectNumber, projectId):
        return '@{}'.format(service_account.split('@')[-1]) in self.managed_service_accounts \
               and (service_account.split('@')[0] == 'service-{}'.format(projectNumber) or \
                    service_account.split('@')[0] == 'project-{}'.format(projectNumber) or \
                    service_account.split('@')[0] == projectNumber or service_account.split('@')[0] == projectId)

    @classmethod
    def from_dict(cls, data):
        """

        Throws:
            ValidationError if the data object does not match the required schema.
        """
        schema_validate(data, cls.SCHEMA)
        return cls(data['managed_service_accounts'])


# Object for confirming that a given org is whitelisted
class GoogleOrgWhitelist(ServiceObjectBase):
    SCHEMA = {
        'type': 'object',
        'properties': {
            'google_org_whitelist': {
                'type': 'array',
                'items': {
                    'type': 'string'
                }
            }
        },
        'required': [
            'google_org_whitelist'
        ]
    }

    def __init__(self, google_org_whitelist):
        self.google_org_whitelist = set(google_org_whitelist)

    def is_whitelisted(self, org_id_number):
        return org_id_number in self.google_org_whitelist

    @classmethod
    def from_dict(cls, data):
        """

        Throws:
            ValidationError if the data object does not match the required schema.
        """
        schema_validate(data, cls.SCHEMA)
        return cls(data['google_org_whitelist'])


# Object confirming that a given service account is black/whitelited
class ServiceAccountBlacklist(ServiceObjectBase):
    SCHEMA = {
        'type': 'object',
        'properties': {
            'service_account_blacklist': {
                'type': 'array',
                'items': {
                    'type': 'string'
                }
            }
        },
        'required': [
            'service_account_blacklist'
        ]
    }

    def __init__(self, service_account_blacklist):
        self.service_account_blacklist = set(service_account_blacklist)

    def is_blacklisted(self, service_account_email):
        return service_account_email in self.service_account_blacklist

    @staticmethod
    def get_django_values():
        """
        Returns a set of service account emails from the Django settings object.
        """
        values = []

        try:
            from django.conf import settings
            values.append(settings.CLIENT_EMAIL)
            values.append(settings.WEB_CLIENT_ID)
        except Exception as e:
            logger.error("Could not read Service Account settings from Django configuration.")
            logger.exception(e)

        return set(values)

    @classmethod
    def from_dict(cls, data):
        """

        Throws:
            ValidationError if the data object does not match the required schema.
        """
        schema_validate(data, cls.SCHEMA)
        return cls(data['service_account_blacklist'])


def is_email_in_iam_roles(roles, user_email):
    """
    Params:
        roles: Dict if which each key is a GCP project role, and value is an array
        of user email without any prefixes.

    Returns: True if user_email is in any role, otherwise False.
    """
    found = False
    for role, user_list in roles.items():
        if user_email.lower() in [user_item['email'].lower() for user_item in user_list]:
            found = True
            break

    return found


def verify_gcp_for_reg(user, gcp_id, is_refresh=False):
    response = {}
    status = None
    try:

        try:
            gcp = GoogleProject.objects.get(project_id=gcp_id, active=1)
            # Can't register the same GCP twice - return immediately
            if not is_refresh:
                return {'message': 'A Google Cloud Project with the project ID {} has already been registered.'.format(gcp_id)}, '400'
        except ObjectDoesNotExist:
            if is_refresh:
                return {'message': 'GCP ID {} does not exist and so cannot be refreshed'.format(str(gcp_id))}, '400'

        crm_service = get_special_crm_resource()
        iam_policy = crm_service.projects().getIamPolicy(resource=gcp_id, body={}).execute()
        bindings = iam_policy['bindings']
        roles = {}

        user_found = False
        fence_sa_found = False

        for val in bindings:
            role = val['role']
            members = val['members']

            for member in members:
                if member.startswith('user:'):
                    email = member.split(':')[1]
                    if email not in roles:
                        roles[email] = {}
                        roles[email]['roles'] = []
                        roles[email]['registered_user'] = bool(User.objects.filter(email=email).first())
                    if user.email.lower() == email.lower():
                        user_found = True
                    roles[email]['roles'].append(role)
                if member.startswith('serviceAccount:'):
                    email = member.split(':')[1]
                    if settings.DCF_MONITORING_SA.lower() == email.lower():
                        fence_sa_found = True

        if not user_found:
            logger.error("[ERROR] While attempting to {} GCP ID {}: ".format(
                "register" if not is_refresh else "refresh",gcp_id)
            )
            logger.error("User {} was not found on GCP {}'s IAM policy.".format(user.email,gcp_id))
            status = '403'
            response['message'] = 'Your user email ({}) was not found in GCP {}. You may not {} a project you do not belong to.'.format(user.email,gcp_id,"register" if not is_refresh else "refresh")
            if is_refresh:
                gcp.user.set(gcp.user.all().exclude(id=user.id))
                gcp.save()
        else:
            response = {'roles': roles, 'gcp_id': gcp_id}
            status = '200'
            if not fence_sa_found:
                logger.warning("[WARNING] DCF Fence SA was not added to the IAM policy for GCP {}".format(gcp_id))
                response['message'] = "The DCF Monitoring Service Account {} was not added to your project's IAM ".format(settings.DCF_MONITORING_SA) \
                    + "policies. Note that without this Service Account added to your project you will not be able to access controlled data."

    except Exception as e:
        if type(e) is HttpError:
            logger.error("[ERROR] While trying to access IAM policies for GCP ID {}:".format(gcp_id))
            response['message'] = 'There was an error accessing this project. Please verify that you have entered the correct Google Cloud Project ID--not the Number or the Name--and set the permissions correctly.'
            status = '400'
        else:
            logger.error("[ERROR] While trying to verify GCP ID {}:".format(gcp_id))
            response['message'] = 'There was an error while attempting to verify this project. Please verify that you have entered the correct Google Cloud Project ID--not the Number or the Name--and set the permissions correctly.'
            status = '500'
        logger.exception(e)

    return response, status


def register_or_refresh_gcp(user, gcp_id, user_list, is_refresh=False):

    response = None
    status = None

    try:
        # log the reports using Cloud logging API
        st_logger = StackDriverLogger.build_from_django_settings()
        log_name = GCP_REG_LOG_NAME

        crm_service = get_special_crm_resource()

        project = crm_service.projects().get(projectId=gcp_id).execute()

        project_name = project['name']

        gcp_users = User.objects.filter(email__in=user_list)

        if not user:
            raise Exception("User not provided.")
        elif not gcp_id:
            raise Exception("GCP Project ID not provided. ")
        elif not len(user_list) or not gcp_users.count():
            # A set of users to register or refresh is required
            msg = "[STATUS] No registered user set found for GCP {} of project {}; {} aborted.".format(
                "refresh" if is_refresh else "registration",gcp_id,"refresh" if is_refresh else "registration")
            logger.warn(msg)
            st_logger.write_text_log_entry(log_name,msg)
            response = {'message': "The registered user set was empty, so the project could not be {}.".format(
                "refreshed" if is_refresh else "registered")
            }
            status = 400
            return response, status
        else:
            try:
                gcp = GoogleProject.objects.get(project_id=gcp_id, active=1)
                if not is_refresh:
                    response = {'message': "A Google Cloud Project with the id {} already exists.".format(gcp_id)}
                    status = 400
                    return response, status

            except ObjectDoesNotExist:
                gcp, created = GoogleProject.objects.update_or_create(
                    project_name=project_name,project_id=gcp_id,
                    defaults={
                       'big_query_dataset': '',
                       'active': 1
                    }
                )
                gcp.save()
                if not created:
                    msg="[STATUS] User {} has re-registered GCP {}".format(User.objects.get(id=user.id).email, gcp_id)
                    logger.info(msg)
                    st_logger.write_text_log_entry(log_name,msg)

        msg = None

        if is_refresh:
            if project_name != gcp.project_name:
                gcp.project_name = project_name

            users_to_add = gcp_users.exclude(id__in=gcp.user.all())
            users_to_remove = gcp.user.all().exclude(id__in=gcp_users)
            if len(users_to_add):
                msg = "The following user{} added to GCP {}: {}".format(
                    ("s were" if len(users_to_add) > 1 else " was"),
                    gcp_id,
                    ", ".join(users_to_add.values_list('email',flat=True)))
            else:
                msg = "There were no new users to add to GCP {}.".format(gcp_id)
            if len(users_to_remove):
                msg += " The following user{} removed from GCP {}: {}".format(
                    ("s were" if len(users_to_remove) > 1 else " was"),
                    gcp_id,
                    ", ".join(users_to_remove.values_list('email',flat=True)))
            else:
                msg += " There were no users to remove from GCP {}.".format(gcp_id)
        else:
            msg = "GCP {} has been successfully registered. ".format(gcp_id) + \
                    "The following users can now access this project from their Account Details " + \
                    "page: {}".format("; ".join(user_list))

        response = {'message': msg}
        
        gcp.user.set(gcp_users)
        gcp.save()

        if not gcp.user.all().count():
            raise Exception("GCP {} has no users!".format(gcp_id))

        status = 200
        reg_type = "NEW GCP REGISTRATION"
        if is_refresh:
            reg_type = "GCP REFRESH"

        st_logger.write_text_log_entry(
            GCP_REG_LOG_NAME,"[{}] User {} has {} GCP {} at {}".format(
                reg_type,
                User.objects.get(id=user.id).email,
                ("refreshed" if is_refresh else "registered"),
                gcp.project_id, datetime.datetime.utcnow()
            )
        )

        return response, status

    except Exception as e:
        logger.error("[ERROR] While {} a Google Cloud Project:".format("refreshing" if is_refresh else "registering"))
        logger.exception(e)
        response = {'message': str(e)}
        status = 500

    return response, status


def unreg_gcp(user, gcp_id):
    
    response = {}
    status = 200
    
    try:
    
        logger.info("[STATUS] User {} is unregistering GCP {}".format(user.email,gcp_id))
        #
        # In the new DCF-centric world, the user has to be logged into DCF if they are trying to
        # delete a project with a service account on it. But users who have never been anywhere near
        # DCF can register projects just to use webapp services.
        # So, if user HAS EVER linked to DCF, they gotta be logged in to do this. If not, then if someone
        # else on the project HAS EVER linked to DCF, they gotta be logged in. If nobody fits that bill,
        # we let them delete the project.
        # Note we also catch the case where a user not on a project is trying to delete it (requires custom
        # crafted POST):
        #

        gcp = GoogleProject.objects.get(id=gcp_id, active=1)
        deleter_analysis = get_project_deleters(gcp.project_id, user.email, logger, SERVICE_ACCOUNT_LOG_NAME)
        if 'message' in deleter_analysis:
            response['message'] = deleter_analysis['message']
            status=400

        do_sa_unregister = True
        if not deleter_analysis['this_user_registered']:
            if deleter_analysis['some_user_registered']:
                response['message'] = "Only a project member who has registered with the Data Commons Framework can unregister this project"
                logger.info("[STATUS] User {} with no DCF status tried to unregister {}".format(user.email, gcp_id))
                status=403
                return response, status
            else: # Nobody on the project has ever done an NIH Linking. Skip the SA step...
                do_sa_unregister = False

        if do_sa_unregister:
            success, msgs = unregister_all_gcp_sa(user.id, gcp_id, gcp.project_id)
            # If we encounter problems deleting SAs, stop the process:
            if not success:
                response['message'] = "Unregistering service accounts from Data Commons Framework was not successful."
                logger.info("[STATUS] SA Unregistration was unsuccessful {}".format(user.email, gcp_id))
                for msg in msgs:
                    response['message'] += "\n{}".format(msg)
                    status=400
                    return response, status        
            logger.info("[STATUS] User {} is unregistering GCP {}: SAs dropped".format(user.email, gcp_id))
            
        gcp.user.clear()
        gcp.active=False
        gcp.save()
        logger.info("[STATUS] User {} has unregistered GCP {}".format(user.email, gcp_id))

    except TokenFailure:
        response['message'] = "Your Data Commons Framework identity needs to be reestablished to complete this task."
        status=403
    except InternalTokenError:
        response['message'] = "There was an unexpected internal error {}. Please contact feedback@isb-cgc.org.".format("1931")
        status=400
    except RefreshTokenExpired:
        response['message'] = "Your login to the Data Commons Framework has expired. You will need to log in again."
        status=403
    except DCFCommFailure:
        response['message'] = "There was a communications problem contacting the Data Commons Framework."
        status=500
    except Exception as e:
        logger.error("[ERROR]: Unexpected Exception {}".format(str(e)))
        response['message'] = "Encountered an error while trying to delete this Google Cloud Project - please contact feedback@isb-cgc.org."
        status=500

    return response, status

