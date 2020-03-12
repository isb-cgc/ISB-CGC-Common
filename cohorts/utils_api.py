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
import re
import logging

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from .models import Cohort, Cohort_Perms, Filters, Filter_Group
from idc_collections.models import Attribute, DataVersion


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
                "patientID":patient,
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

def get_filterSet_api(cohort):
    attributes = {}
    filter_group = cohort.filter_group_set.get()
    filters = filter_group.filters_set.all()
    for filter in filters:
        attributes[filter.attribute.name] = filter.value.split(",")

    filterset = {
        "bioclin_version": filter_group.data_versions.get(name='TCGA Clinical and Biospecimen Data').version,
        "imaging_version": filter_group.data_versions.get(name='TCIA Image Data').version,
        "attributes": attributes
    }

    return filterset

def _delete_cohort_api(user, cohort_id):
    cohort_info = None

    try:
        cohort = Cohort.objects.get(id=cohort_id)
    except ObjectDoesNotExist:
        cohort_info = "A cohort with the ID {} was not found!".format(cohort_id)
    else:
        try:
            Cohort_Perms.objects.get(user=user, cohort=cohort, perm=Cohort_Perms.OWNER)
        except ObjectDoesNotExist:
            cohort_info = "{} isn't the owner of cohort ID {} and so cannot delete it.".format(user.email, cohort.id)
        else:
            try:
                cohort = Cohort.objects.get(id=cohort_id, active=True)
                cohort.active = False
                cohort.save()
                cohort_info = 'Cohort ID {} has been deleted.'.format(cohort_id)
            except ObjectDoesNotExist:
                cohort_info = 'Cohort ID {} was previously deleted.'.format(cohort_id)
    return cohort_info


def _save_cohort_api(user, name, data, case_insens=True):

    description = data['description']
    filterset = data['filterSet']
    attributes = filterset["attributes"]
    cohort_id = 'cohort_id' in data and data['cohort_id'] or None


    if not filterset or not name:
        # Can't save/edit a cohort when nothing is being changed!
        return {
            "message": "Can't save a cohort with no information to save! (Name and filters not provided.)",
            "code": 400
            }

    blacklist = re.compile(BLACKLIST_RE, re.UNICODE)
    match = blacklist.search(str(name))
    if match:
        # XSS risk, log and fail this cohort save
        match = blacklist.findall(str(name))
        logger.error('[ERROR] While saving a cohort, saw a malformed name: ' + name + ', characters: ' + str(match))
        return {
            'message': "Your cohort's name contains invalid characters; please choose another name.",
            "code": 400
            }

    # If we're only changing the name, just edit the cohort and update it
    if cohort_id:
        cohort = Cohort.objects.get(id=cohort_id)
        cohort.name = name
        cohort.save()
        return {'cohort_id': cohort.id}

    # Make and save cohort
    cohort = Cohort.objects.create(name=name, description=description)
    cohort.save()

    perm = Cohort_Perms(cohort=cohort, user=user, perm=Cohort_Perms.OWNER)
    perm.save()

    # For now, any set of filters in a cohort is a single 'group'; this allows us to, in the future,
    # let a user specify a different operator between groups (eg. (filter a AND filter b) OR (filter c AND filter D)
    grouping = Filter_Group.objects.create(resulting_cohort=cohort, operator=Filter_Group.AND)

    # Get versions of datasets to be filtered, and link to filter group
    imaging_version = 'imaging_version' in filterset and \
                      len(DataVersion.objects.filter(name='TCIA Image Data', version=filterset['imaging_version'])) == 1 and \
                      DataVersion.objects.get(name='TCIA Image Data', version=filterset['imaging_version']) or \
                      DataVersion.objects.get(active=True, name='TCIA Image Data')
    grouping.data_versions.add(imaging_version)

    bioclin_version = 'bioclin_version' in filterset and \
                      len(DataVersion.objects.filter(name='TCGA Clinical and Biospecimen Data', version=filterset['bioclin_version'])) == 1 and \
                      DataVersion.objects.get(name='TCGA Clinical and Biospecimen Data', version=filterset['bioclin_version']) or \
                      DataVersion.objects.get(active=True, name='TCGA Clinical and Biospecimen Data')
    grouping.data_versions.add(bioclin_version)


    for attr in attributes:
        filter_values = attributes[attr]
        attr_id = Attribute.objects.get(name=attr)
        Filters.objects.create(resulting_cohort=cohort, attribute=attr_id, value=",".join(filter_values), filter_group=grouping).save()

    cohort_info = {
        "id": cohort.id,
        "name": cohort.name,
        "description": cohort.description,
        "filterSet": get_filterSet_api(cohort)
    }
    return cohort_info


