from django.conf import settings

import requests
import logging
import json
from projects.models import DataSource, Attribute_Ranges, Attribute
import re

from metadata_utils import MOLECULAR_CATEGORIES

logger = logging.getLogger('main_logger')

SOLR_URI = settings.SOLR_URI
SOLR_LOGIN = settings.SOLR_LOGIN
SOLR_PASSWORD = settings.SOLR_PASSWORD
SOLR_CERT = settings.SOLR_CERT

BMI_MAPPING = {
    'underweight': '[* TO 18.5}',
    'normal': '[18.5 TO 25}',
    'overweight': '[25 TO 30}',
    'obese': '[30 TO *]'
}


# Combined query and result formatter method
# optionally will normalize facet counting so the response structure is the same for facets+docs and just facets
def query_solr_and_format_result(query_settings, normalize_facets=True, normalize_groups=True):
    formatted_query_result = {}

    try:
        result = query_solr(**query_settings)

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
            if normalize_facets:
                formatted_query_result['facets'] = {}
                for facet in result['facets']:
                    if not re.search('_count', facet) and facet != 'count':
                        facet_counts = result['facets'][facet]
                        if 'buckets' in facet_counts:
                            # This is a standard term facet
                            formatted_query_result['facets'][facet] = {}
                            if 'missing' in facet_counts:
                                formatted_query_result['facets'][facet]['None'] = facet_counts['missing']['unique_count'] if 'unique_count' in facet_counts['missing'] else facet_counts['missing']['count']
                            for bucket in facet_counts['buckets']:
                                formatted_query_result['facets'][facet][bucket['val']] = bucket['unique_count'] if 'unique_count' in bucket else bucket['count']
                        else:
                            # This is a query facet
                            facet_name = facet.split(":")[0]
                            display_range = facet.split(":")[1]
                            query_range = facet.split(":")[-1]
                            if facet_name not in formatted_query_result['facets']:
                                formatted_query_result['facets'][facet_name] = {}
                            formatted_query_result['facets'][facet_name]["{}::{}".format(display_range,query_range)] = facet_counts['count']
                    else:
                        formatted_query_result[facet] = result['facets'][facet]
            else:
                formatted_query_result['facets'] = result['facets']
        elif 'facet_counts' in result:
                formatted_query_result['facets'] = result['facet_counts']['facet_fields']

        if 'stats' in result:
            formatted_query_result['values'] = {
                x: result['stats']['stats_fields'][x]['distinctValues'] for x in result['stats']['stats_fields']
            }

    except Exception as e:
        logger.error("[ERROR] While querying solr and formatting result:")
        logger.exception(e)
        print("Excepted result:")
        print(result)

    return formatted_query_result

# Execute a POST request to the solr server available available at settings.SOLR_URI
def query_solr(collection=None, fields=None, query_string=None, fqs=None, facets=None, sort=None, counts_only=True,
               collapse_on=None, offset=0, limit=1000, unique=None, distincts=None):

    query_uri = "{}{}/query".format(SOLR_URI, collection)

    payload = {
        "query": query_string or "*:*",
        "limit": 0 if counts_only else limit,
        "offset": offset,
        "params": {
            "debugQuery": "on"
        }
    }

    param_set = ""

    if facets:
        payload['facet'] = facets
    if unique:
        if not facets:
            payload['facet'] = {}
        payload['facet']['unique_count'] = "unique({})".format(unique)
    if fields:
        payload['fields'] = fields
    if sort:
        payload['sort'] = sort
    if fqs:
        payload['filter'] = fqs if type(fqs) is list else [fqs]
    if distincts:
        payload['params']['stats'] = True
        payload['params']['stats.field'] = ["{!distinctValues=true}%s"%x for x in distincts]

    if len(param_set):
        query_uri += ("?"+param_set)

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
        query_response = requests.post(query_uri, data=json.dumps(payload), headers={'Content-type': 'application/json'}, auth=(SOLR_LOGIN, SOLR_PASSWORD), verify=SOLR_CERT)
        if query_response.status_code != 200:
            msg = "Saw response code {} when querying solr collection {} with string {}\npayload: {}\nresponse text: {}".format(
                str(query_response.status_code), collection, query_string, payload,
                query_response.text
            )
            raise Exception(msg)
        query_result = query_response.json()
    except Exception as e:
        logger.error("[ERROR] While querying solr collection {}:".format(collection, query_string))
        logger.exception(e)

    return query_result


# Solr facets are the bucket counting; optionally provide a set of filters to *not* be counted for purposes of
# providing counts on the query filters
# attrs: Attribute QuerySet
# filter_tags: If there are filters to be excluded via tagging, this is the dict mapping attribute name to filter tag
# include_nulls: will include missing=True for facets where data wasn't included
# unique: If counts need to be calculated against a specific field, this is that field as a string (otherwise counts are document-wise)
def build_solr_facets(attrs, filter_tags=None, include_nulls=True, unique=None, total_facets=None):
    facets = {}
    for attr in attrs:
        facet_type = DataSource.get_facet_type(attr)
        if facet_type == "query":
            # We need to make a series of query buckets
            attr_ranges = Attribute_Ranges.objects.filter(attribute=attr)
            for attr_range in attr_ranges:
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
                    if filter_tags and attr.name in filter_tags:
                        facets[facet_name]['domain'] = {
                            "excludeTags": filter_tags[attr.name]
                        }

                    if unique:
                        facets[facet_name]['facet'] = {"unique_count": "unique({})".format(unique)}

                    null_facet_name = "{}:{}".format(attr.name,"None")
                    if include_nulls and null_facet_name not in facets:
                        facets[null_facet_name] = {
                            'type': facet_type,
                            'field': attr.name,
                            'limit': -1,
                            'q': '-(+(%s:{* TO *}))' % attr.name
                        }

                else:
                    # Iterated range
                    cast = int if attr_range.type == Attribute_Ranges.INT else float
                    unit = cast(attr_range.unit)
                    gap = cast(attr_range.gap)
                    last = cast(attr_range.last)
                    lower = cast(attr_range.first)
                    upper = cast(attr_range.first)+gap

                    if attr_range.unbounded:
                        upper = lower
                        lower = "*"

                    while lower == "*" or lower < last:
                        upper_display = str(upper-(0 if attr_range.include_upper else unit))
                        lower_display = lower if lower == "*" else str(lower+(0 if attr_range.include_lower else unit))
                        facet_name = "{}:{}".format(
                            attr.name, attr_range.label
                        ) if attr_range.label else "{}:{} to {}:{} to {}".format(
                            attr.name, lower_display, upper_display, str(lower), str(upper)
                        )
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
                        if unique:
                            facets[facet_name]['facet'] = {"unique_count": "unique({})".format(unique)}

                        lower = upper
                        upper = lower+gap

                    # If we stopped *at* the end, we need to add one last bucket.
                    if attr_range.unbounded:
                        last_display = str(last+(unit if attr_range.include_upper else 0))
                        facet_name = "{}:{}".format(
                            attr.name, attr_range.label
                        ) if attr_range.label else "{}:{} to {}:{} to {}".format(
                            attr.name, last_display, "*", str(last), "*"
                        )
                        facets[facet_name] = {
                            'type': facet_type,
                            'field': attr.name,
                            'limit': -1,
                            'q': "{}:{}{} TO {}]".format(attr.name, l_boundary, str(attr_range.last), "*")
                        }

                        if filter_tags and attr.name in filter_tags:
                            facets[facet_name]['domain'] = {
                                "excludeTags": filter_tags[attr.name]
                            }

                        if unique:
                            facets[facet_name]['facet'] = {"unique_count": "unique({})".format(unique)}

                    if include_nulls:
                        none_facet_name = "{}:None".format(attr.name)
                        facets[none_facet_name] = {
                            'type': facet_type,
                            'field': attr.name,
                            'limit': -1,
                            'q': '-{}:[* TO *]'.format(attr.name)
                        }

                        if filter_tags and attr.name in filter_tags:
                            facets[none_facet_name]['domain'] = {
                                "excludeTags": filter_tags[attr.name]
                            }

                        if unique:
                            facets[none_facet_name]['facet'] = {"unique_count": "unique({})".format(unique)}
        else:
            facets[attr.name] = {
                'type': facet_type,
                'field': attr.name,
                'limit': -1
            }

            if filter_tags and attr.name in filter_tags:
                facets[attr.name]['domain'] = {
                    "excludeTags": filter_tags[attr.name]
                }

            if include_nulls:
                facets[attr.name]['missing'] = True

            if unique:
                facets[attr.name]['facet'] = {"unique_count": "unique({})".format(unique)}

    if total_facets:
        for count in total_facets:
            facets["{}_count".format(count)] = "unique({})".format(count)

    return facets



# Build a query string for Solr
def build_solr_query(filters, comb_with='OR', with_tags_for_ex=False, tag_offset=0, subq_join_field=None, do_not_exclude=None):

    continuous_num = Attribute.get_ranged_attrs(False)
    continuous_num_list = list(continuous_num.values_list('name',flat=True))
    attr_ranges = Attribute_Ranges.objects.select_related('attribute').filter(attribute__in=continuous_num)

    first = True
    full_query_str = ''
    query_set = None
    filter_tags = None
    count = 0+tag_offset
    mutation_filters = {}
    main_filters = {}

    # Because mutation filters can be OR'd, split them out separately:
    for attr, values in list(filters.items()):
        if 'MUT:' in attr:
            mutation_filters[attr] = values
        else:
            main_filters[attr] = values

    for attr, values in list(mutation_filters.items()):
        if type(values) is dict and 'values' in values:
            values = values['values']

        if type(values) is not list:
            if type(values) is str and "," in values:
                values = values.split(',')
            else:
                values = [values]

        # If it's first in the list, don't append your combinator
        if first:
            first = False
        else:
            if not with_tags_for_ex:
                full_query_str += ' {} '.format(comb_with)

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
                    values_filter += ("(\"" + "\" \"".join(MOLECULAR_CATEGORIES[val]['attrs']) + "\")")
        else:
            values_filter += ("(\"" + "\" \"".join(values) + "\")")

        query = '(+%s:("%s") AND +%s:%s)' % (gene_field, gene, attr_name, values_filter)

        if invert:
            inverted_query = "{!join to=%s from=%s}%s" % (
                subq_join_field, subq_join_field, query.replace("\"", "\\\"")
            )
            query_str = ' (*:* -_query_:"{}")'.format(inverted_query)
        else:
            query_str = query

        query_set = query_set or {}
        full_query_str += query_str

        if with_tags_for_ex and ((do_not_exclude is None) or (attr not in do_not_exclude)):
            filter_tags = filter_tags or {}
            tag = "f{}".format(str(count))
            filter_tags[attr] = tag
            query_str = ("{!tag=%s}" % tag)+query_str
            count += 1

        query_set[attr] = query_str

    for attr, values in list(main_filters.items()):
        query_str = ''

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
                full_query_str += ' AND '

        # If it's looking for a single None value
        if len(values) == 1 and values[0] == 'None':
            query_str += '(-%s:{* TO *})' % attr
        # If it's a ranged value, calculate the bins
        elif attr == 'bmi':
            clause = " {} ".format(comb_with).join(["{}:{}".format(attr, BMI_MAPPING[x]) for x in values if x != 'None'])
            if 'None' in values:
                query_str += '-(-(%s) +(%s:{* TO *}))' % (clause, attr)
            else:
                query_str += "(+({}))".format(clause)
        elif attr in continuous_num_list or attr[:attr.rfind('_')] in continuous_num_list:
            attr_name = attr[:attr.rfind('_')] if re.search('_[gl]t[e]|_btw',attr) else attr
            # We need to check the include upper/lower settings to make sure we filter our set right
            first_range = attr_ranges.filter(attribute__name=attr_name).first()
            l_boundary = "[" if first_range.include_lower else "{"
            u_boundary = "]" if first_range.include_upper else "}"
            if len(values) > 1 and type(values[0]) is list:
                clause = " {} ".format(comb_with).join(
                    ["{}:[{}{} TO {}{}]".format(attr_name, l_boundary, str(x[0]), str(x[1]), u_boundary) for x in values if x!= 'None'])
            elif len(values) > 1:
                values_temp = values.copy()
                if 'None' in values_temp:
                    values_temp.remove('None')
                if type(values[0] is str) and re.search(" [Tt][Oo] ",values_temp[0]):
                    clause = " {} ".format(comb_with).join(
                        ["{}:{}{}{}".format(attr_name, l_boundary, x.upper(), u_boundary) for x in values_temp])
                else:
                    clause = "{}:{}{} TO {}{}".format(attr_name, l_boundary, values_temp[0], values_temp[1], u_boundary)

            else:
                if re.search('_[gl]t[e]',attr):
                    clause = "{}:{}".format(attr_name, values[0])
                else:
                    clause = "{}:{}{}{}".format(attr_name, l_boundary, values[0].upper(), u_boundary)

            if 'None' in values:
                query_str += '-(-(%s) +(%s:{* TO *}))' % (clause, attr_name)
            else:
                query_str += "(+({}))".format(clause)
        else:
            if 'None' in values:
                query_str += '(-(-(%s:("%s")) +(%s:{* TO *})))' % (attr,"\" \"".join([str(y) for y in values if y!= 'None']), attr)
            else:
                query_str += '(+%s:(%s))' % (attr, " ".join(["{}{}{}".format('"' if "*" not in str(y) else '',str(y),'"' if "*" not in str(y) else '') for y in values]))

        query_set = query_set or {}
        full_query_str += query_str

        if with_tags_for_ex and ((do_not_exclude is None) or (attr not in do_not_exclude)):
            filter_tags = filter_tags or {}
            tag = "f{}".format(str(count))
            filter_tags[attr] = tag
            query_str = ("{!tag=%s}" % tag)+query_str
            count += 1

        query_set[attr] = query_str

    return {
        'queries': query_set,
        'full_query_str': full_query_str,
        'filter_tags': filter_tags,
        'tag_count': count
    }
