from django.conf import settings

import requests
import logging
import json

from metadata_utils import MOLECULAR_CATEGORIES

logger = logging.getLogger('main_logger')

SOLR_URI = settings.SOLR_URI
SOLR_LOGIN = settings.SOLR_LOGIN
SOLR_PASSWORD = settings.SOLR_PASSWORD


RANGE_FIELDS = ['wbc_at_diagnosis', 'event_free_survival', 'days_to_death', 'days_to_last_known_alive', 'days_to_last_followup', 'age_at_diagnosis', 'year_of_diagnosis']

BMI_MAPPING = {
    'underweight': '[* TO 18.5}',
    'normal weight': '[18.5 TO 25}',
    'overweight': '[25 TO 30)',
    'obese': '[30 TO *]'
}

# Combined query and result formatter method
# optionally will normalize facet counting so the response structure is the same for facets+docs and just facets
def query_solr_and_format_result(query_settings, normalize_facets=True, normalize_groups=True):
    formatted_query_result = {}

    try:
        result = query_solr(**query_settings)

        formatted_query_result['numFound'] = result['response']['numFound']

        if 'grouped' in result:
            if normalize_groups:
                formatted_query_result['groups'] = []
                for group in result['grouped']:
                    for val in result['grouped'][group]['groups']:
                        for doc in val['doclist']['docs']:
                            doc[group] = val['groupValue']
                            formatted_query_result['groups'].append(doc)
            else:
                formatted_query_result['groups'] = result['grouped']

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
def query_solr(collection=None, fields=None, query_string=None, fq_string=None, facets=None, sort=None, counts_only=True, collapse_on=None, offset=0, limit=1000):
    query_uri = "{}{}/query".format(SOLR_URI, collection)

    payload = {
        "query": query_string or "*:*",
        "limit": 0 if counts_only else limit,
        "offset": offset,
    }

    if facets:
        payload['facet'] = facets
    if fields:
        payload['fields'] = fields
    if sort:
        payload['sort'] = sort
        
    if (not fq_string and collapse_on) or (not collapse_on and fq_string):
        payload['filter'] = fq_string or '{!collapse field=%s}' % collapse_on
    else:
        payload['params'] = {
            'fq': [fq_string, '{!collapse field=%s}' % collapse_on]
        }

    query_result = {}

    try:
        query_response = requests.post(query_uri, data=json.dumps(payload), headers={'Content-type': 'application/json'}, auth=(SOLR_LOGIN, SOLR_PASSWORD))
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
                'field': attr,
                'limit': -1
            }
            if include_nulls:
                facets[attr]['missing'] = True

    return facets


# Build a query string for Solr
def build_solr_query(filters, comb_with='OR'):

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
            elif key == 'bmi':
                if 'None' in value:
                    value.remove('None')
                    query_str += ' -(-(%s) +(%s:{* TO *}))' % (" OR ".join(["{}:{}".format(key, BMI_MAPPING[x]) for x in value]), key)
                else:
                    query_str += " +({})".format(" OR ".join(["{}:{}".format(key, BMI_MAPPING[x]) for x in value]))
            elif key in RANGE_FIELDS:
                if 'None' in value:
                    value.remove('None')
                    query_str += ' -(-(%s) +(%s:{* TO *}))' % (" OR ".join(["{}:[{}]".format(key, x.upper()) for x in value]), key)
                else:
                    query_str += " +({})".format(" OR ".join(["{}:[{}]".format(key, x.upper()) for x in value]))
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
