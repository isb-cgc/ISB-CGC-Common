from django.conf import settings

import requests
import logging
import json


from metadata.query_helpers import sql_age_by_ranges, sql_bmi_by_ranges, sql_simple_days_by_ranges, sql_simple_number_by_200, sql_year_by_ranges, MOLECULAR_CATEGORIES
from projects.models import Program

logger = logging.getLogger('main_logger')

SOLR_URI = settings.SOLR_URI


# Combined query and result formatter method
# optionally will normalize facet counting so the response structure is the same for facets+docs and just facets
def query_solr_and_format_result(query_settings, normalize_facets=True):
    formatted_query_result = {}

    try:
        result = query_solr(**query_settings)

        formatted_query_result['numFound'] = result['response']['numFound']

        if 'docs' in result['response'] and len(result['response']['docs']):
            formatted_query_result['docs'] = result['response']['docs']

        if 'facets' in result:
            if normalize_facets:
                formatted_query_result['facets'] = {}
                for facet in result['facets']:
                    if facet != 'count':
                        formatted_query_result['facets'][facet] = {}
                        facet_counts = result['facets'][facet]
                        if 'missing' in facet_counts:
                            formatted_query_result['facets'][facet]['None'] = facet_counts['missing']['count']
                        for bucket in facet_counts['buckets']:
                            formatted_query_result['facets'][facet][bucket['val']] = bucket['count']
            else:
                formatted_query_result['facets'] = result['facets']
        elif 'facet_counts' in result:
                formatted_query_result['facets'] = result['facet_counts']['facet_fields']
    except Exception as e:
        logger.error("[ERROR] While querying solr and formatting result:")
        logger.exception(e)

    return formatted_query_result


# Execute a POST request to the solr server available available at settings.SOLR_URI
def query_solr(collection=None, fields=None, query_string=None, fq_string=None, facets=None, sort=None, counts_only=True, offset=0, limit=1000):
    query_uri = "{}{}/query".format(SOLR_URI, collection)

    payload = {
        "query": query_string or "*:*",
        "limit": 0 if counts_only else limit,
        "offset": offset,
    }

    if facets:
        payload['facet'] = facets
    if fq_string:
        payload['filter'] = fq_string
    if fields:
        payload['fields'] = fields
    if sort:
        payload['sort'] = sort

    query_result = {}

    try:
        query_response = requests.post(query_uri, data=json.dumps(payload), headers={'Content-type': 'application/json'})
        if query_response.status_code != 200:
            raise Exception("Saw response code {} when querying solr collection {} with string {}".format(str(query_response.status_code), collection, query_string))
        query_result = query_response.json()
    except Exception as e:
        logger.error("[ERROR] While querying solr collection {} with string {}".format(collection, query_string))
        logger.exception(e)

    return query_result


# Solr facets are the bucket counting; optionally provide a set of filters to *not* be counted for purposes of
# providing counts on the query filters
def build_solr_facets(attr_set, filters=None, include_nulls=True):
    facets = {}
    for attr in attr_set:
        if not filters or attr not in filters:
            facets[attr] = {
                'type': 'terms',
                'field': attr
            }
            if include_nulls:
                facets[attr]['missing'] = True

    return facets


# Build a query string for Solr
def build_solr_query(filters, program=None, for_files=False, comb_with='OR'):

    first = True
    query_str = ''
    key_order = []
    keyType = None

    for key, value in list(filters.items()):
        gene = None
        invert = False

        if isinstance(value, dict) and 'values' in value:
            value = value['values']

        if isinstance(value, list) and len(value) == 1:
            value = value[0]

        if key == 'data_type' and not for_files:
            key = 'metadata_data_type_availability_id'

        # Multitable where's will come in with : in the name. Only grab the column piece for now
        # TODO: Shouldn't throw away the entire key
        elif ':' in key:
            keyType = key.split(':')[0]
            if keyType == 'MUT':
                gene = key.split(':')[2]
                invert = bool(key.split(':')[3] == 'NOT')
            key = key.split(':')[-1]

        # Multitable filter lists don't come in as string as they can contain arbitrary text in values
        elif isinstance(value, str):
            # If it's a list of values, split it into an array
            if ',' in value:
                value = value.split(',')

        key_order.append(key)

        # BQ-only format
        if keyType == 'MUT':
            # If it's first in the list, don't append an "and"
            if first:
                first = False
            else:
                query_str += ' {}'.format(comb_with)

            query_str += " (%s:(%s) AND " % ('Hugo_Symbol', gene,)

            if(key == 'category'):
                if value == 'any':
                    query_str += '(%s:{* TO *}' % 'Variant_Classification'
                else:
                    values = MOLECULAR_CATEGORIES[value]['attrs']
                    query_str += '(%s%s:(%s))'.format("-" if invert else "", 'Variant_Classification', " ".join(values))
            else:
                values = value
                query_str += '(%s%;s:(%s))'.format("-" if invert else "", 'Variant_Classification', " ".join(values))
        else:
            # If it's first in the list, don't append an "and"
            if first:
                first = False
            else:
                query_str += ' AND'

            # If it's looking for a single None value
            if value == 'None' or (isinstance(value, list) and len(value) == 1 and value[0] == 'None'):
                query_str += ' (-%s:{* TO *})' % key
            # If it's a ranged value, calculate the bins
            elif key == 'age_at_diagnosis':
                query_str += ' +(' + sql_age_by_ranges(value,(program and Program.objects.get(id=program).name == 'TARGET')) + ') '
            elif key == 'bmi':
                query_str += ' +(' + sql_bmi_by_ranges(value) + ') '
            elif key == 'year_of_diagnosis':
                query_str += ' +(' + sql_year_by_ranges(value) + ') '
            elif key == 'event_free_survival' or key == 'days_to_death' or key == 'days_to_last_known_alive' or key == 'days_to_last_followup':
                query_str += ' +(' + sql_simple_days_by_ranges(value, key) + ') '
            elif key == 'wbc_at_diagnosis':
                query_str += ' +(' + sql_simple_number_by_200(value, key) + ') '
            elif isinstance(value, list):
                if 'None' in value:
                    value.remove('None')
                    query_str += ' -(-(%s:(%s)) +(%s:{* TO *}))' % (key," ".join(value), key)
                else:
                    query_str += ' (+%s:(%s))' % (key, " ".join(value))
            # A single, non-None value
            else:
                query_str += ' +%s:%s' % (key, value)

    return query_str
