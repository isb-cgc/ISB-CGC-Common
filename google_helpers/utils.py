"""

Copyright 2016-2018, Institute for Systems Biology

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

from googleapiclient import discovery
from googleapiclient.errors import HttpError
from google.appengine.runtime.apiproxy_errors import DeadlineExceededError as APIDeadlineExceededError
from google.appengine.api.urlfetch_errors import DeadlineExceededError as FetchDeadlineExceededError
from google.appengine.api.remote_socket._remote_socket_error import error as GoogleSocketError
from httplib import HTTPException
import logging

logger = logging.getLogger('main_logger')

#
# Use this in place of build() to catch all the bogus Google errors!
#


def build_with_retries(service_tag, version_tag, creds, num_retries, http=None):
    service = None
    retries = num_retries
    while (retries > 0) and (service is None):
        retries -= 1
        try:
            if http:
                service = discovery.build(service_tag, version_tag, http=http, cache_discovery=False)
            else:
                service = discovery.build(service_tag, version_tag, credentials=creds, cache_discovery=False)
        except (APIDeadlineExceededError, FetchDeadlineExceededError, HTTPException, GoogleSocketError) as e:
            if num_retries > 0:
                logger.info('{0} Exception: {1} : {2} : trying {3}'.format(service_tag, str(type(e)), str(e), num_retries))
            else:
                logger.error('{0} Exception: {1} : {2} : gave up {3}'.format(service_tag, str(type(e)), str(e), num_retries))
        except HttpError as e:
            if e.resp.status == 503 or e.resp.status == 500:  # worth a retry on a backend error...
                if num_retries > 0:
                    logger.info('{0} HttpError: {1} : code {2} : trying {3}'.format(service_tag, str(e), e.resp.status,
                                                                                    num_retries))
                else:
                    logger.error('{0} HttpError: {1} : code {2} : gave up {3}'.format(service_tag, str(e), e.resp.status,
                                                                                      num_retries))
            else:
                # Let the caller decide if this is an error or not. Some errors (e.g. removing from a group when user is
                # not there) are expected to occur:
                logger.info('{0} HttpError: {1} : {2} : code {3}'.format(service_tag, str(type(e)), str(e), e.resp.status))
                raise e

        except Exception as e:
            logger.error('{0} (Unexpected) {1}  {2}'.format(service_tag, str(type(e)), str(e)))
            raise e

    return service

#
# Use this in place of execute() to catch all the bogus Google errors!
#


def execute_with_retries(req, task, retries, http=None):
    num_retries = retries
    resp = None
    while (num_retries > 0) and (resp is None):
        num_retries -= 1
        try:
            # Still got a Deadline Exceeded with num_retries=3. Don't bother!
            if http:
                resp = req.execute(http=http)
            else:
                resp = req.execute()
        except (APIDeadlineExceededError, FetchDeadlineExceededError, HTTPException, GoogleSocketError) as e:
            if num_retries > 0:
                logger.info('{0} Exception: {1} : {2} : trying {3}'.format(task, str(type(e)), str(e), num_retries))
            else:
                logger.error('{0} Exception: {1} : {2} : gave up {3}'.format(task, str(type(e)), str(e), num_retries))
        except HttpError as e:
            if e.resp.status == 503 or e.resp.status == 500:  # worth a retry on a backend error...
                if num_retries > 0:
                    logger.info('{0} HttpError: {1} : code {2} : trying {3}'.format(task, str(e), e.resp.status,
                                                                                    num_retries))
                else:
                    logger.error('{0} HttpError: {1} : code {2} : gave up {3}'.format(task, str(e), e.resp.status,
                                                                                      num_retries))
            else:
                # Let the caller decide if this is an error or not. Some errors (e.g. removing from a group when user is
                # not there) are expected to occur:
                logger.info('{0} HttpError: {1} : {2} : code {3}'.format(task, str(type(e)), str(e), e.resp.status))
                raise e

        except Exception as e:
            logger.error('{0} (Unexpected) {1}  {2}'.format(task, str(type(e)), str(e)))
            raise e

    return resp

