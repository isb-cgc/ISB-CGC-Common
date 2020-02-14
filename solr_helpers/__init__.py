from django.conf import settings

import requests
import logging
import json

from metadata.query_helpers import MOLECULAR_CATEGORIES

logger = logging.getLogger('main_logger')

SOLR_URI = settings.SOLR_URI
SOLR_LOGIN = settings.SOLR_LOGIN
SOLR_PASSWORD = settings.SOLR_PASSWORD
SOLR_CERT = settings.SOLR_CERT

RANGE_FIELDS = ['wbc_at_diagnosis', 'event_free_survival', 'days_to_death', 'days_to_last_known_alive', 'days_to_last_followup', 'age_at_diagnosis', 'year_of_diagnosis']

BMI_MAPPING = {
    'underweight': '[* TO 18.5}',
    'normal weight': '[18.5 TO 25}',
    'overweight': '[25 TO 30}',
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
def query_solr(collection=None, fields=None, query_string=None, fqs=None, facets=None, sort=None, counts_only=True, collapse_on=None, offset=0, limit=1000):
    query_uri = "{}{}/query".format(SOLR_URI, collection)

    payload = {
        "query": query_string or "*:*",
        "limit": 0 if counts_only else limit,
        "offset": offset,
        "params": {"debugQuery": "on"}
    }

    if facets:
        payload['facet'] = facets
    if fields:
        payload['fields'] = fields
    if sort:
        payload['sort'] = sort
    if fqs:
        payload['filter'] = fqs if type(fqs) is list else [fqs]

    if collapse_on:
        collapse = '{!collapse field=%s}' % collapse_on
        if fqs:
            payload['filter'].append(collapse)
        else:
            payload['filter'] = [collapse]

    query_result = {}

    try:
        query_response = requests.post(query_uri, data=json.dumps(payload), headers={'Content-type': 'application/json'}, auth=(SOLR_LOGIN, SOLR_PASSWORD), verify=SOLR_CERT)
        if query_response.status_code != 200:
            logger.error(payload)
            logger.error(query_response.json())
            raise Exception("Saw response code {} when querying solr collection {} with string {}".format(str(query_response.status_code), collection, query_string))
        query_result = query_response.json()
    except Exception as e:
        logger.error("[ERROR] While querying solr collection {} with string {}".format(collection, query_string))
        logger.exception(e)

    return query_result


# Solr facets are the bucket counting; optionally provide a set of filters to *not* be counted for purposes of
# providing counts on the query filters
def build_solr_facets(attr_set, filter_tags=None, include_nulls=True):
    facets = {}
    for attr in attr_set:
        facets[attr] = {
            'type': 'terms',
            'field': attr,
            'limit': -1
        }
        if include_nulls:
            facets[attr]['missing'] = True
        if filter_tags and attr in filter_tags:
            facets[attr]['domain'] = {
                "excludeTags": filter_tags[attr]
            }

    return facets


# Build a query string for Solr
def build_solr_query(filters, comb_with='OR', with_tags_for_ex=False):

    first = True
    query_str = ''
    query_set = None
    filter_tags = None
    count = 0

    mutation_filters = {}
    other_filters = {}

    # Split mutation filters into their own set, because of repeat use of the same attrs
    for attr in filters:
        if 'MUT:' in attr:
            mutation_filters[attr] = filters[attr]
        else:
            other_filters[attr] = filters[attr]

    # 'Mutation' filters, special category for MUT: type filters
    for attr, values in list(mutation_filters.items()):
        if type(values) is not list:
            values = [values]
        gene = attr.split(':')[2]
        gene_field = "Hugo_Symbol"
        filter_type = attr.split(':')[-1].lower()
        invert = bool(attr.split(':')[3] == 'NOT')

        # TODO: sort out how we're handling mutations

    for attr, values in list(other_filters.items()):

        if type(values) is dict and 'values' in values:
            values = values['values']

        if type(values) is not list:
            if type(values) is str and "," in values:
                values = values.split(',')
            else:
                values = [values]

        # If it's first in the list, don't append an "and"
        if first:
            first = False
        else:
            if not with_tags_for_ex:
                query_str += ' AND '

        # If it's looking for a single None value
        if len(values) == 1 and values[0] == 'None':
            query_str += '(-%s:{* TO *})' % attr
        # If it's a ranged value, calculate the bins
        elif attr == 'bmi':
            clause = " {} ".format(comb_with).join(["{}:{}".format(attr, BMI_MAPPING[x]) for x in values])
            if 'None' in values:
                values.remove('None')
                query_str += '-(-(%s) +(%s:{* TO *}))' % (clause, attr)
            else:
                query_str += "+({})".format(clause)
        elif attr in RANGE_FIELDS:
            clause = " {} ".format(comb_with).join(["{}:[{} TO {}]".format(attr, str(x[0]), str(x[1])) for x in values])
            if 'None' in values:
                values.remove('None')
                query_str += '-(-(%s) +(%s:{* TO *}))' % (clause, attr)
            else:
                query_str += "+({})".format(clause)
        else:
            if 'None' in values:
                values.remove('None')
                query_str += '-(-(%s:(%s)) +(%s:{* TO *}))' % (attr," ".join(values), attr)
            else:
                query_str += '(+%s:(%s))' % (attr, " ".join(values))

        if with_tags_for_ex:
            query_set = query_set or {}
            filter_tags = filter_tags or {}
            tag = "f{}".format(str(count))
            filter_tags[attr] = tag
            query_set[attr] = ("{!tag=%s}" % tag)+query_str
            query_str = ''
            count += 1

    return {
        'queries': query_set,
        'full_query_str': query_str,
        'filter_tags': filter_tags
    }
