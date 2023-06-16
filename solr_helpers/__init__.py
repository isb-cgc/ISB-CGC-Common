from django.conf import settings

import requests
import logging
import json
import re
import hashlib
import time

from idc_collections.models import Attribute, DataSource, Attribute_Ranges, DataSetType

from metadata.query_helpers import MOLECULAR_CATEGORIES

logger = logging.getLogger('main_logger')

SOLR_URI = settings.SOLR_URI
SOLR_LOGIN = settings.SOLR_LOGIN
SOLR_PASSWORD = settings.SOLR_PASSWORD
SOLR_CERT = settings.SOLR_CERT

BMI_MAPPING = {
    'underweight': '[* TO 18.5}',
    'normal weight': '[18.5 TO 25}',
    'overweight': '[25 TO 30}',
    'obese': '[30 TO *]'
}

# Combined query and result formatter method
# optionally will normalize facet counting so the response structure is the same for facets+docs and just facets
def query_solr_and_format_result(query_settings, normalize_facets=True, normalize_groups=True, raw_format=False):
    formatted_query_result = {}
    try:
        result = query_solr(**query_settings)
        if raw_format:
            formatted_query_result = result
        else:
            if 'grouped' in result:
                formatted_query_result['numFound'] = result['grouped'][list(result['grouped'].keys())[0]]['matches']
                if normalize_groups:
                    formatted_query_result['groups'] = []
                    for group in result['grouped']:
                        for val in result['grouped'][group]['groups']:
                            for doc in val['doclist']['docs']:
                                doc[group] = val['groupValue']
                                formatted_query_result['groups'].append(doc)
                else:
                    formatted_query_result['groups'] = result['grouped']
            else:
                formatted_query_result['numFound'] = result['response']['numFound']

            if 'response' in result and 'docs' in result['response'] and len(result['response']['docs']):
                formatted_query_result['docs'] = result['response']['docs']
            else:
                formatted_query_result['docs'] = []

            if 'facets' in result:
                if 'unique_count' in result['facets']:
                    formatted_query_result['totalNumFound'] = formatted_query_result['numFound']
                    formatted_query_result['numFound'] = result['facets']['unique_count']
                if 'instance_size' in result['facets']:
                    formatted_query_result['total_instance_size'] = result['facets']['instance_size']
                if normalize_facets:
                    formatted_query_result['facets'] = {}
                    for facet in result['facets']:
                        check_facet = re.search('^(unique|total)_(.+)$',facet)
                        if facet not in ['count', 'unique_count', 'instance_size'] and not check_facet :
                            facet_counts = result['facets'][facet]
                            if 'buckets' in facet_counts:
                                # This is a term facet
                                formatted_query_result['facets'][facet] = {}
                                if 'missing' in facet_counts:
                                    formatted_query_result['facets'][facet]['None'] = facet_counts['missing']['unique_count'] if 'unique_count' in facet_counts['missing'] else facet_counts['missing']['count']
                                for bucket in facet_counts['buckets']:
                                    formatted_query_result['facets'][facet][bucket['val']] = bucket['unique_count'] if 'unique_count' in bucket else bucket['count']
                            else:
                                # This is a query facet
                                facet_name = facet.split(":")[0]
                                facet_range = facet.split(":")[-1]
                                if facet_name not in formatted_query_result['facets']:
                                    formatted_query_result['facets'][facet_name] = {}
                                if facet_range == 'min_max':
                                    formatted_query_result['facets'][facet_name][facet_range] = facet_counts
                                else:
                                    formatted_query_result['facets'][facet_name][facet_range] = facet_counts['unique_count'] if 'unique_count' in facet_counts else facet_counts['count']
                        elif check_facet:
                            newFacet = check_facet.group(2)
                            which = "{}s".format(check_facet.group(1))
                            if which not in formatted_query_result:
                                formatted_query_result[which] = {}
                            formatted_query_result[which][newFacet] = result['facets'][facet]
                else:
                    formatted_query_result['facets'] = result['facets']
            elif 'facet_counts' in result:
                formatted_query_result['facets'] = result['facet_counts']['facet_fields']

            if 'stats' in result:
                for attr in result['stats']['stats_fields']:
                    if attr in formatted_query_result['facets']:
                        formatted_query_result['facets'][attr]["min_max"] = {
                            'min': result['stats']['stats_fields'][attr]['min'] or 0,
                            'max': result['stats']['stats_fields'][attr]['max'] or 0
                        }

            formatted_query_result['nextCursor'] = result.get('nextCursorMark',None)

    except Exception as e:
        logger.error("[ERROR] While querying solr and formatting result:")
        logger.exception(e)

    return formatted_query_result


# Execute a POST request to the solr server available available at settings.SOLR_URI
def query_solr(collection=None, fields=None, query_string=None, fqs=None, facets=None, sort=None, counts_only=True,
               collapse_on=None, offset=0, limit=1000, uniques=None, with_cursor=None, stats=None, totals=None):
    query_uri = "{}{}/query".format(SOLR_URI, collection)

    payload = {
        "query": query_string or "*:*",
        "limit": 0 if counts_only else limit,
        "offset": offset if not with_cursor else 0,
        "params": {
            "debugQuery": "on"
        }
    }

    if with_cursor:
        payload['params']['cursorMark'] = with_cursor

    if stats:
        payload['params']['stats'] = True
        payload['params']['stats.field'] = stats

    if facets:
        payload['facet'] = facets
    if uniques:
        if not facets:
            payload['facet'] = {}
        ufield =  uniques.pop(0)
        for x in uniques:
            payload['facet']['unique_{}'.format(x)] = {
                'type': 'terms',
                'field': ufield,
                'limit': -1,
                'missing': True,
                'facet': {
                    'unique_count': 'unique({})'.format(x)
                }
            }
    if totals:
        if not facets:
            payload['facet'] = {}
        for x in totals:
            payload['facet']['total_{}'.format(x)] = 'unique({})'.format(x)

    if fields:
        payload['fields'] = fields
    if sort or with_cursor:
        # If we're using a cursor, we must include the uniqueKey in the sorting priority
        payload['sort'] = "{}".format("{}, id asc".format(sort) if with_cursor and sort else sort if sort else "id asc")
    if fqs:
        payload['filter'] = fqs if type(fqs) is list else [fqs]

    # Note that collapse does NOT allow for proper faceted counting of facets where documents may have more than one entry
    # in such a case, build a unique facet in the facet builder
    if collapse_on:
        collapse = '{!collapse field=%s}' % collapse_on
        if fqs:
            payload['filter'].append(collapse)
        else:
            payload['filter'] = [collapse]

    query_result = {}

    try:
        start = time.time()

        query_response = requests.post(query_uri, data=json.dumps(payload), headers={'Content-type': 'application/json'}, auth=(SOLR_LOGIN, SOLR_PASSWORD), verify=SOLR_CERT)
        stop = time.time()

        logger.info("[BENCHMARKING] Time to call Solr via POST to core {}: {}s".format(collection,str(stop-start)))

        if query_response.status_code != 200:
            msg = "Saw response code {} when querying solr collection {} with string {}\npayload: {}\nresponse text: {}".format(
                str(query_response.status_code), collection, payload['query'], payload,
                query_response.text
            )
            raise Exception(msg)
        query_result = query_response.json()
    except Exception as e:
        logger.error("[ERROR] While querying solr collection {}:".format(collection, payload['query']))
        logger.exception(e)

    return query_result


# Generates the Solr stats block of a JSON API request
def build_solr_stats(attrs,filter_tags=None):
    stats = []
    attr_facets = attrs.get_facet_types()
    for attr in attrs:
        if attr_facets[attr.id] == 'query':
            stat = attr.name
            if filter_tags and attr.name in filter_tags:
                stat = "{!ex=%s}"%filter_tags[attr.name]+stat
            stats.append(stat)
    return stats

# Solr facets are the bucket counting; optionally provide a set of filters to *not* be counted for purposes of
# providing counts on the query filters
def build_solr_facets(attrs, filter_tags=None, include_nulls=True, unique=None, with_stats=False):
    facets = {}

    attr_sets = attrs.get_attr_sets()
    attr_cats = attrs.get_attr_cats()
    attr_facets = attrs.get_facet_types()
    attr_ranges = attrs.get_attr_ranges(True)
    cat_attrs = {}
    for attr in attr_cats:
        cat = attr_cats[attr]
        if cat['cat_name'] not in cat_attrs:
            cat_attrs[cat['cat_name']] = []
        if attr not in cat_attrs[cat['cat_name']]:
            cat_attrs[cat['cat_name']].append(attr)

    for attr in attrs:
        facet_type = attr_facets[attr.id]
        facet_name = attr.name
        if facet_type == "query":
            # We need to make a series of query buckets
            for attr_range in attr_ranges[attr.id]:
                u_boundary = "]" if attr_range.include_upper else "}"
                l_boundary = "[" if attr_range.include_lower else "{"
                if attr_range.gap == "0":
                    # This is a single range, no iteration to be done
                    lower = attr_range.first
                    upper = attr_range.last
                    facet_name = "{}:{}".format(attr.name, attr_range.label) if attr_range.label else "{}:{} to {}".format(attr.name, str(lower), str(upper))
                    facets[facet_name] = {
                        'type': facet_type,
                        'field': attr.name,
                        'limit': -1,
                        'q': "{}:{}{} TO {}{}".format(attr.name, l_boundary, str(lower), str(upper), u_boundary)
                    }
                    if unique:
                        facets[facet_name]['facet'] = {"unique_count": "unique({})".format(unique)}

                    if DataSetType.DERIVED_DATA in attr_sets.get(attr.name, []) and attr.name in attr_cats:
                        if not 'domain' in facets[facet_name]:
                            facets[facet_name]['domain'] = {}
                        facets[facet_name]['domain']['filter'] = "has_{}:True".format(
                            attr_cats[attr.name]['cat_name'].lower())

                    if filter_tags and attr.name in filter_tags:
                        if not 'domain' in facets[facet_name]:
                            facets[facet_name]['domain'] = {}
                        facets[facet_name]['domain']["excludeTags"] = filter_tags[attr.name]
                else:
                    # Iterated range
                    cast = int if attr_range.type == Attribute_Ranges.INT else float
                    gap = cast(attr_range.gap)
                    last = cast(attr_range.last)
                    lower = cast(attr_range.first)
                    upper = cast(attr_range.first)+gap

                    if attr_range.unbounded:
                        upper = lower
                        lower = "*"

                    while lower == "*" or lower < last:
                        facet_name = "{}:{}".format(attr.name, attr_range.label) if attr_range.label else "{}:{} to {}".format(attr.name, str(lower), str(upper))
                        facets[facet_name] = {
                            'type': facet_type,
                            'field': attr.name,
                            'limit': -1,
                            'q': "{}:{}{} TO {}{}".format(attr.name, l_boundary, str(lower), str(upper), u_boundary)
                        }
                        if filter_tags and attr.name in filter_tags:
                            facets[facet_name]['domain'] = {
                                "excludeTags": filter_tags[attr.name]
                            }
                        lower = upper
                        upper = lower+gap

                        if unique:
                            facets[facet_name]['facet'] = {"unique_count": "unique({})".format(unique)}

                        if DataSetType.DERIVED_DATA in attr_sets.get(attr.name, []) and attr.name in attr_cats:
                            if not 'domain' in facets[facet_name]:
                                facets[facet_name]['domain'] = {}
                            facets[facet_name]['domain']['filter'] = "has_{}:True".format(
                                attr_cats[attr.name]['cat_name'].lower())

                        if filter_tags and attr.name in filter_tags:
                            if not 'domain' in facets[facet_name]:
                                facets[facet_name]['domain'] = {}
                            facets[facet_name]['domain']["excludeTags"] = filter_tags[attr.name]

                    # If we stopped *at* the end, we need to add one last bucket.
                    if attr_range.unbounded:
                        facet_name = "{}:{}".format(attr.name, attr_range.label) if attr_range.label else "{}:{} to {}".format(attr.name, str(attr_range.last), "*")
                        facets[facet_name] = {
                            'type': facet_type,
                            'field': attr.name,
                            'limit': -1,
                            'q': "{}:{}{} TO {}]".format(attr.name, l_boundary, str(attr_range.last), "*")
                        }
                        if unique:
                            facets[facet_name]['facet'] = {"unique_count": "unique({})".format(unique)}

                        if DataSetType.DERIVED_DATA in attr_sets.get(attr.name, []) and attr.name in attr_cats:
                            if not 'domain' in facets[facet_name]:
                                facets[facet_name]['domain'] = {}
                            facets[facet_name]['domain']['filter'] = "has_{}:True".format(
                                attr_cats[attr.name]['cat_name'].lower())

                        if filter_tags and attr.name in filter_tags:
                            if not 'domain' in facets[facet_name]:
                                facets[facet_name]['domain'] = {}
                            facets[facet_name]['domain']["excludeTags"] = filter_tags[attr.name]

            if include_nulls:
                none_facet_name = "{}:None".format(attr.name)
                facets[none_facet_name] = {
                    'type': facet_type,
                    'field': attr.name,
                    'limit': -1,
                    'q': '-{}:[* TO *]'.format(attr.name)
                }

                if unique:
                    facets[none_facet_name]['facet'] = {"unique_count": "unique({})".format(unique)}

                # We need to make domain filters to exclude anything from outside this category or we'll get a bunch of NULLs from
                # other categories' records
                if DataSetType.DERIVED_DATA in attr_sets.get(attr.name, []) and attr.name in attr_cats:
                    if not 'domain' in facets[none_facet_name]:
                        facets[none_facet_name]['domain'] = {}
                    if 'filter' not in facets[none_facet_name]['domain']:
                        facets[none_facet_name]['domain']['filter'] = ""
                    facets[none_facet_name]['domain']['filter'] += "has_{}:True".format(attr_cats[attr.name]['cat_name'].lower())

        else:
            facets[attr.name] = {
                'type': facet_type,
                'field': attr.name,
                'limit': -1
            }

            if filter_tags and attr.name in filter_tags:
                if not 'domain' in facets[attr.name]:
                    facets[attr.name]['domain'] = {}
                facets[attr.name]['domain']["excludeTags"] =  filter_tags[attr.name]

            if include_nulls:
                facets[attr.name]['missing'] = True

            if unique:
                facets[attr.name]['facet'] = {"unique_count": "unique({})".format(unique)}

            if DataSetType.DERIVED_DATA in attr_sets.get(attr.name, []) and attr.name in attr_cats:
                if not 'domain' in facets[facet_name]:
                    facets[facet_name]['domain'] = {}
                facets[facet_name]['domain']['filter'] = "has_{}:True".format(attr_cats[attr.name]['cat_name'].lower())

    return facets


# Build a query string for Solr
#
# filters: filter dict of one of these forms:
# {
#    <attribute name>: [<value1>,[<value2>...]],
# }
#
# {
#    <attribute name>: {'values': [<value1>,[<value2>...]], 'op': [<OR>|<AND>]},
# }
#
# value_op: Controls the operator used in filtering the values of a given field (OR | AND, default OR)
#
# comb_with: Controls the operator used in combining filters (OR | AND, default AND)
#
# with_tags_for_ex: Boolean toggle for the creation and tracking dict of filter exclusion tags to be used in faceting
#
# subq_join_field: If inverted filters are present, subq_join_field determines the field used to {!join} the inverted
# subquery to the main query
#
# search_child_records_by: a dict indicating what field, if any, should be used in subquerying 'child' or related records.
# This allows for searching on 'related records' which are being filtered out based on lack of a filter value, but which
# satisfy another criteria - eg., records from the same study may not all have the same fields pulled out, but you may
# still want those records when filtering on this attribute.
#
def build_solr_query(filters, comb_with='AND', with_tags_for_ex=False, subq_join_field=None,
                     search_child_records_by=None, global_value_op='OR'):

    # subq_join not currently used in IDC
    ranged_attrs = Attribute.get_ranged_attrs()
    first = True
    full_query_str = ''
    query_set = None
    filter_tags = None
    count = 0
    mutation_filters = {}
    main_filters = {}
    search_child_records_by = search_child_records_by or {}

    date_attrs = ['StudyDate']

    # Because mutation filters can have their operation specified, split them out separately:
    for attr, values in list(filters.items()):
        if 'MUT:' in attr:
            mutation_filters[attr] = values
        else:
            main_filters[attr] = values

    # Mutation filters, not currently applicable in IDC
    for attr, values in list(mutation_filters.items()):
        if type(values) is dict and 'values' in values:
            value_op = values['op'] or value_op
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
                full_query_str += ' {} '.format(value_op)

        attr_name = 'Variant_Classification'
        gene_field = "Hugo_Symbol"
        gene = attr.split(':')[2]
        filter_type = attr.split(':')[-1].lower()
        invert = bool(re.search("\:NOT\:", attr))

        values_filter = ''
        if filter_type == 'category':
            if values[0].lower() == 'any':
                values_filter = "*"
            else:
                for val in values:
                    values_filter += ("(\"" + "\" \"".join(MOLECULAR_CATEGORIES[val]) + "\")")
        else:
            values_filter += ("(\"" + "\" \"".join(values) + "\")")

        query = '(+%s:("%s") AND +%s:%s)' % (gene_field, gene, attr_name, values_filter)

        if invert:
            inverted_query = "{!join to=%s from=%s}%s" % (
                subq_join_field, subq_join_field, query.replace("\"", "\\\"")
            )
            query_str = ' (-_query_:"{}")'.format(inverted_query)
        else:
            query_str = query

        query_set = query_set or {}
        full_query_str += query_str

        if with_tags_for_ex:
            filter_tags = filter_tags or {}
            tag = "f{}".format(str(count))
            filter_tags[attr] = tag
            query_str = ("{!tag=%s}" % tag)+query_str
            count += 1

        query_set[attr] = query_str

    # All other filters
    for attr, values in list(main_filters.items()):
        value_op = global_value_op
        if type(values) is dict and 'values' in values:
            value_op = values['op'] or global_value_op
            values = values['values']
        attr_name = attr[:attr.rfind('_')] if re.search('_[gl]t[e]|_e?btwe?',attr) else attr
        attr_rng = attr[attr.rfind('_')+1:] if re.search('_[gl]t[e]|_e?btwe?', attr) else ''

        query_str = ''

        if type(values) is dict and 'values' in values:
            values = values['values']

        if type(values) is not list:
            if type(values) is str and "," in values:
                values = values.split(',')
            else:
                values = [values]

        # All individual (nonlist) values MUST be cast to string; numbers cannot be combined using join
        values = [str(x).replace('"','\\"') if not isinstance(x,list) else x for x in values]
        # If it's first in the list, don't append an "and"
        if first:
            first = False
        else:
            if not with_tags_for_ex:
                full_query_str += ' {} '.format(comb_with)

        # If it's looking for a single None value
        if len(values) == 1 and values[0] == 'None':
            query_str += '(-%s:{* TO *})' % attr_name
        # If it's a ranged value, calculate the bins
        elif attr_name == 'bmi':
            with_none = False
            if 'None' in values:
                values.remove('None')
                with_none = True
            clause = " {} ".format(value_op).join(["{}:{}".format(attr, BMI_MAPPING[x]) for x in values])
            query_str += (('-(-(%s) +(%s:{* TO *}))' % (clause, attr)) if with_none else "+({})".format(clause))
        elif attr_name in ranged_attrs or attr_name in date_attrs:
            bounds = ("[" if re.search('^ebtwe?',attr_rng) else "{{","]" if re.search('e?btwe$',attr_rng) else "}}",)
            rngTemp = "{}:%s{} TO {}%s" % bounds

            clause = ""
            with_none = False
            if 'None' in values:
                values.remove('None')
                with_none = True

            if len(values) >= 1 and type(values[0]) is str and re.match(r'\d+ [tT][oO] \d+', values[0]):
                values[0] = values[0].lower().split(" to ")

            if attr_name in date_attrs:
                date_temp_first = "{}T:00:00:00Z"
                date_temp_second = "{}T:11:59:99Z"
                if len(values) >= 1 and type(values[0]) is list:
                    clause = " {} ".format(value_op).join(
                        [rngTemp.format(attr_name, date_temp_first.format(x[0]),date_temp_second.format(x[1])) for x in values])
                else:
                    clause = rngTemp.format(
                        attr_name,
                        date_temp_first.format(values[0]),
                        date_temp_second.format(values[-1])
                    )
            else:
                if len(values) >= 1 and type(values[0]) is list:
                    clause = " {} ".format(value_op).join(
                        [rngTemp.format(attr_name, str(x[0]), str(x[1])) for x in values])
                elif len(values) > 1 :
                    clause = rngTemp.format(attr_name, values[0], values[1])
                else:
                    clause = "{}:{}".format(attr_name, values[0])

            query_str += (('(-(-(%s) +(%s:{* TO *})))' % (clause, attr_name)) if with_none else "(+({}))".format(clause))

        else:
            vals = "\" {} \"".format(value_op).join(values)
            if 'None' in values:
                values.remove('None')
                query_str += '(-(-(%s:("%s")) +(%s:{* TO *})))' % (attr_name,vals, attr_name)
            else:
                query_str += '(+%s:("%s"))' % (attr_name, vals)

        query_set = query_set or {}

        if search_child_records_by.get(attr_name, None):
            query_str = '({} OR ({} +_query_:"{}"))'.format(query_str, '(-%s:{* TO *})' % attr_name,
                    "{!join to=%s from=%s}%s" % (search_child_records_by[attr_name], search_child_records_by[attr_name],
                                                 query_str.replace("\"", "\\\"")))

        full_query_str += query_str

        if with_tags_for_ex:
            filter_tags = filter_tags or {}
            tag = "f{}".format(str(count))
            filter_tags[attr_name] = tag
            query_str = ("{!tag=%s}" % tag)+query_str
            count += 1

        query_set[attr_name] = query_str

    return {
        'queries': query_set,
        'full_query_str': full_query_str,
        'filter_tags': filter_tags
    }
