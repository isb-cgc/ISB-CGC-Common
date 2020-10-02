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

import logging
import copy

from django.conf import settings
from idc_collections.models import ImagingDataCommonsVersion
from idc_collections.collex_metadata_utils import get_bq_metadata, get_bq_string


logger = logging.getLogger('main_logger')
BLACKLIST_RE = settings.BLACKLIST_RE


def build_collections(objects, dois, urls):
    collections = []
    for collection in objects:
        patients = build_patients(collection, objects[collection], dois, urls)
        collections.append(
            {
                "collection_id":collection,
            }
        )
        if len(patients) > 0:
            collections[-1]["patients"] = patients
    return collections


def build_patients(collection,collection_patients, dois, urls):
    patients = []
    for patient in collection_patients:
        studies = build_studies(collection, patient, collection_patients[patient], dois, urls)
        patients.append({
                "patient_id":patient,
            }
        )
        if len(studies) > 0:
            patients[-1]["studies"] = studies
    return patients


def build_studies(collection, patient, patient_studies, dois, urls):
    studies = []
    for study in patient_studies:
        series = build_series(collection, patient, study, patient_studies[study], dois, urls)
        studies.append(
            {
                "StudyInstanceUID": study
            })
        if dois:
            studies[-1]["GUID"] = ""
        if urls:
            studies[-1]["AccessMethods"] = [
                    {
                        "access_url": "gs://gcs-public-data--healthcare-tcia-{}/dicom/{}".format(collection,study),
                        "region": "Multi-region",
                        "type": "gs"
                    }
            ]
        if len(series) > 0:
            studies[-1]["series"] = series
    return studies


def build_series(collection, patient, study, patient_studies, dois, urls):
    series = []
    for aseries in patient_studies:
        instances = build_instances(collection, patient, study, aseries, patient_studies[aseries], dois, urls)
        series.append(
            {
                "SeriesInstanceUID": aseries
            })
        if dois:
            series[-1]["GUID"] = ""
        if urls:
            series[-1]["AccessMethods"] = [
                {
                    "access_url": "gs://gcs-public-data--healthcare-tcia-{}/dicom/{}/{}".format(collection,
                                    study, aseries),
                    "region": "Multi-region",
                    "type": "gs"
                }
            ]
        if len(instances) > 0:
            series[-1]["instances"] = instances
    return series


def build_instances(collection, patient, study, series, study_series, dois, urls):
    instances = []
    for instance in study_series:
        instances.append(
            {
                "SOPInstanceUID": instance
            })
        if dois:
            instances[-1]["GUID"] = ""
        if urls:
            instances[-1]["AccessMethods"] = [
                {
                    "access_url": "gs://gcs-public-data--healthcare-tcia-{}/dicom/{}/{}/{}.dcm".format(collection,
                                    study,series,instance),
                    "region": "Multi-region",
                    "type": "gs"
                }
            ]
    return instances


def build_hierarchy(objects, rows, return_level, reorder):
#
    for raw in rows:
        rawv = [val['v'] for val in raw['f']]
        row = [rawv[i] for i in reorder]
        row[0] = row[0].replace('_','-')
        if not row[0] in objects:
            objects[row[0]] = {}
        if return_level == 'Collection':
            continue
        if not row[1] in objects[row[0]]:
            objects[row[0]][row[1]] = {}
        if return_level == 'Patient':
            continue
        if not row[2] in objects[row[0]][row[1]]:
            objects[row[0]][row[1]][row[2]] = {}
        if return_level == 'Study':
            continue
        if not row[3] in objects[row[0]][row[1]][row[2]]:
            objects[row[0]][row[1]][row[2]][row[3]] = []
        if return_level == 'Series':
            continue
        if not row[4] in objects[row[0]][row[1]][row[2]][row[3]]:
            # objects[row[0]][row[1]][row[2]][row[3]][row[4]] = {}
            objects[row[0]][row[1]][row[2]][row[3]].append(row[4])
    return objects

def get_idc_version(version_number=None):
    if not version_number:
        # No version specified. Use the current version
        data_version = ImagingDataCommonsVersion.objects.get(active=True)
    else:
        data_version = ImagingDataCommonsVersion.objects.get(version_number=version_number)
    return data_version


# Get the filterSet of a cohort
# get_filters_as_dict returns an array of filter groups, but can currently only define
# a filter of one group. So take just the first group and also delete the attribute id
def get_filterSet_api(cohort):

    version = cohort.get_data_versions()[0].version_number
    filter_group = cohort.get_filters_as_dict()[0]

    filterSet = {'idc_version': version}
    filters = {filter['name']: filter['values'] for filter in filter_group['filters']}
    filterSet['filters'] = filters
    return filterSet

def get_cohort_objects(request, filters, data_version, cohort_info):

    levels = {'Instance': ['collection_id', 'PatientID', 'StudyInstanceUID', 'SeriesInstanceUID', 'SOPInstanceUID'],
              'Series': ['collection_id', 'PatientID', 'StudyInstanceUID', 'SeriesInstanceUID'],
              'Study': ['collection_id', 'PatientID', 'StudyInstanceUID'],
              'Patient': ['collection_id', 'PatientID'],
              'Collection': ['collection_id'],
              'None': []
              }

    rows_left = fetch_count = int(request.GET['fetch_count'])
    page = int(request.GET['page'])
    return_level = request.GET['return_level']
    select = levels[return_level]
    offset = int(request.GET['offset']) + (fetch_count * (page - 1))
    objects = {}
    all_rows = []

    # Get the SQL
    sql = ""
    if request.GET['return_sql'] in [True, 'True']:
        sql += "\t({})\n\tUNION ALL\n".format(get_bq_string(
            filters=filters, fields=select, data_version=data_version,
            order_by=select[-1:]))
    cohort_info['cohort']['sql'] = sql


    totalReturned = 0
    collections = []
    if request.GET['return_level'] != "None":
        # We first build a tree of just the object IDS: collection_ids, PatientIDs, StudyInstanceUID,...
        while rows_left > 0:
            results = get_bq_metadata(
                filters=filters, fields=select, data_version=data_version,
                limit=min(fetch_count, settings.MAX_BQ_RECORD_RESULT), offset=offset,
                order_by=select[-1:])
            if results['totalFound'] == None:
                # If there are not as many rows as asked for, we're done with BQ
                break

            # returned has the number of rows actually returned by the query
            returned = len(results["results"])

            totalReturned += returned
            fetch_count -= returned

            # Create a list of the fields in the returned schema
            fields = [field['name'] for field in results['schema']['fields']]
            # Build a list of indices into fields that tells build_hierarchy how to reorder
            reorder = [fields.index(x) for x in select]

            # rows holds the actual data
            rows = results['results']
            all_rows.extend(rows)

            # unFound is the number of rows we haven't yet obtained from BQ
            unFound = rows_left - returned
            if unFound >= 0:
                #  We need to add all the rows just received from BQ to the hierarchy
                objects = build_hierarchy(
                    objects=objects,
                    rows=rows,
                    reorder=reorder,
                    return_level=return_level)
                rows_left -= returned
                offset += returned
                if returned < min(fetch_count, settings.MAX_BQ_RECORD_RESULT):
                    # We got all there is to get
                    break
            elif unFound == 0:
                # We have all we need
                objects = build_hierarchy(
                    objects=objects,
                    rows=rows,
                    reorder=reorder,
                    return_level=return_level)
                break
            else:
                # If we got more than requested by user, trim the list of rows received from BQ
                objects = build_hierarchy(
                    objects=objects,
                    rows=rows[:unFound],
                    reorder=reorder,
                    return_level=return_level)
                break

        # Then we add the details such as DOI, URL, etc. about each object
        # dois = request.GET['return_DOIs'] in ['True', True]
        # urls = request.GET['return_URLs'] in ['True', True]
        dois = False
        urls = False
        collections = build_collections(objects, dois, urls)

    cohort_info['cohort']["cohortObjects"] = {
        "rowsReturned": totalReturned,
        "collections": collections,
        # "rows": schema_rows if request.GET["return_rows"] in ['True', True] else []
    }

    return cohort_info

def _cohort_detail_api(request, cohort, cohort_info):

    filter_group = cohort.filter_group_set.get()
    filters = filter_group.get_filter_set()
    for filter in filters:
        if filter == 'collection_id':
            collections = []
            for collection in filters['collection_id']:
                collections.append(collection.lower().replace('-', '_'))
            filters['collection_id'] = collections

    # data_versions = filter_group.data_versions.all()
    data_version = filter_group.data_version

    # cohort_info = get_cohort_objects(request, filters, data_versions, cohort_info)
    cohort_info = get_cohort_objects(request, filters, data_version, cohort_info)

    return cohort_info

def form_rows(data):
    rows = []
    for row in data:
        if  row['f'][0]['v'] != None:
           rows.append(row['f'][0]['v'])
    return rows

# Get a list of GCS URLs or CRDC DOIs of the instances in the cohort
def get_cohort_instances(request, filters, data_version, cohort_info):

    rows_left = fetch_count = int(request.GET['fetch_count'])
    page = int(request.GET['page'])
    access_method = request.GET['access_class']

    select = ['gcs_url'] if access_method == 'url' else ['crdc_instance_uuid']
    offset = int(request.GET['offset']) + (fetch_count * (page - 1))
    objects = {}
    totalReturned = 0
    all_rows = []
    sql = ""

    # We first build a tree of just the object IDS: collection_ids, PatientIDs, StudyInstanceUID,...
    while rows_left > 0:
        # Accumulate the SQL for each call
        # sql += "\t({})\n\tUNION ALL\n".format(get_bq_string(
        #     filters=filters, fields=select, data_versions=data_versions,
        #     limit=min(fetch_count, settings.MAX_BQ_RECORD_RESULT), offset=offset,
        #     order_by=select[-1:]))

        results = get_bq_metadata(
            filters=filters, fields=select, data_version=data_version,
            limit=min(fetch_count, settings.MAX_BQ_RECORD_RESULT), offset=offset,
            order_by=select[-1:])
        if results['totalFound'] == None:
            # If there are not as many rows as asked for, we're done with BQ
            break

        # rows holds the actual data
        rows = form_rows(results['results'])
        # returned has the number of rows actually returned by the query
        returned = len(rows)

        totalReturned += returned
        fetch_count -= returned

        # unFound is the number of rows we haven't yet obtained from BQ
        unFound = rows_left - returned
        if unFound >= 0:
            rows_left -= returned
            offset += returned
            # all_rows.extend(urls)
            all_rows.extend(rows)
            if returned < min(fetch_count, settings.MAX_BQ_RECORD_RESULT):
                # We got all there is to get
                break
        elif unFound == 0:
            break
        else:
            # If we got more than requested by user, trim the list of rows received from BQ
            # all_rows.extend(urls[:unFound])
            all_rows.extend(rows[:unFound])
            break

    cohort_info["manifest"]["accessMethods"] = dict(
                type = "gs",
                region = "us",
                urls = all_rows if access_method == 'url' else [],
                dois = all_rows if access_method != 'url' else []
    )

    return cohort_info

def _cohort_manifest_api(request, cohort, cohort_info):

    filter_group = cohort.filter_group_set.get()
    filters = filter_group.get_filter_set()
    for filter in filters:
        if filter == 'collection_id':
            collections = []
            for collection in filters['collection_id']:
                collections.append(collection.lower().replace('-', '_'))
            filters['collection_id'] = collections

    data_version = filter_group.data_version

    cohort_info = get_cohort_instances(request, filters, data_version, cohort_info)

    cohort_info['manifest']["filterSet"] = get_filterSet_api(cohort)

    return cohort_info


def _cohort_preview_manifest_api(request, data, cohort_info):
    filters = data['filterSet']['filters']

    if not filters:
        # Can't save/edit a cohort when nothing is being changed!
        return {
            "message": "Can't save a cohort with no information to save! (Name and filters not provided.)",
            "code": 400
            }
    if 'collection_id' in filters:
        filters['collection_id'] = [collection.lower().replace('-', '_') for collection in filters['collection_id']]


    # Get versions of datasets to be filtered, and link to filter group
    if not data['filterSet']['idc_version']:
        # No version specified. Use the current version
        data_version = ImagingDataCommonsVersion.objects.get(active=True)
    else:
        try:
            data_version = ImagingDataCommonsVersion.objects.get(version_number=data['filterSet']['idc_version'])
        except:
            return dict(
                message = "Invalid IDC version {}".format(data['filterSet']['idc_version']),
                code = 400
            )

    cohort_info = get_cohort_instances(request, filters, data_version, cohort_info)

    cohort_info['manifest']["filterSet"] = copy.deepcopy(data['filterSet'])
    cohort_info['manifest']["filterSet"]['idc_version'] = data_version.version_number

    return cohort_info


def _cohort_preview_api(request, data, cohort_info, data_version):
    filters = data['filterSet']['filters']

    if not filters:
        # Can't save/edit a cohort when nothing is being changed!
        return {
            "message": "Can't save a cohort with no information to save! (Name and filters not provided.)",
            "code": 400
            }

    if 'collection_id' in filters:
        filters['collection_id'] = [collection.lower().replace('-', '_') for collection in filters['collection_id']]

    cohort_info = get_cohort_objects(request, filters, data_version, cohort_info)

    return cohort_info


