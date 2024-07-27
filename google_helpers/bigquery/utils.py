#
# Copyright 2015-2023, Institute for Systems Biology
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

from builtins import str
import re
import copy
import logging
from google.cloud.bigquery import ArrayQueryParameter, ScalarQueryParameter, StructQueryParameter

logger = logging.getLogger(__name__)

# Some attribute types will fool the type checker due to their content; we hard code
# these as STRING
FIXED_TYPES = {
    'SeriesInstanceUID': 'STRING',
    'StudyInstanceUID': 'STRING',
    'PatientID': 'STRING',
    'Manufacturer': 'STRING',
    'ManufacturerModelName': 'STRING',
    'StudyDate': 'DATE'
}

MOLECULAR_CATEGORIES = {
    'nonsilent': {
        'name': 'Non-silent',
        'attrs': [
            'Missense_Mutation',
            'Nonsense_Mutation',
            'Nonstop_Mutation',
            'Frame_Shift_Del',
            'Frame_Shift_Ins',
            'In_Frame_Del',
            'In_Frame_Ins',
            'Translation_Start_Site',
        ]
    }
}

# Builds a BQ API v2 QueryParameter set and WHERE clause string from a set of filters of the form:
# {
#     'field_name': [<value>,...]
# }
# Breaks out '<ATTR> IS NULL'
# 2+ values are converted to IN (<value>,...)
# Filters must already be pre-bucketed or formatted
# Use of LIKE is detected based on single-length value array and use of % in the value string
# Support special 'mutation' filter category
# Support for Greater/Less than (or equal to) via [gl]t[e]{0,1} in attr name,
#     eg. {"age_at_diagnosis_gte": [50,]}
# Support for BETWEEN via _btw in attr name, eg. ("wbc_at_diagnosis_btw": [800,1200]}
# Support for providing an explicit schema of the fields being searched
#
# TODO: add support for DATES


def build_bq_filter_and_params(filters, comb_with='AND', param_suffix=None, with_count_toggle=False,
                               field_prefix=None, type_schema=None, case_insens=True):
    result = {
        'filter_string': '',
        'parameters': []
    }

    if with_count_toggle:
        result['count_params'] = {}

    filter_set = []

    mutation_filters = {}
    other_filters = {}

    # Split mutation filters into their own set, because of repeat use of the same attrs
    for attr in filters:
        if 'MUT:' in attr:
            mutation_filters[attr] = filters[attr]
        else:
            other_filters[attr] = filters[attr]

    mut_filtr_count = 1
    # 'Mutation' filters, special category for MUT: type filters
    for attr, values in list(mutation_filters.items()):
        if type(values) is not list:
            values = [values]
        gene = attr.split(':')[2]
        filter_type = attr.split(':')[-1].lower()
        invert = bool(attr.split(':')[3] == 'NOT')
        param_name = 'gene{}{}'.format(str(mut_filtr_count), '_{}'.format(param_suffix) if param_suffix else '')
        filter_string = '{}Hugo_Symbol = @{} AND '.format('' if not field_prefix else field_prefix, param_name)

        gene_query_param = ScalarQueryParameter(param_name, 'STRING', gene)

        var_query_param = None

        if filter_type == 'category' and values[0].lower() == 'any':
            filter_string += '{}Variant_Classification IS NOT NULL'.format('' if not field_prefix else field_prefix, )
            var_query_param = None
        else:
            if filter_type == 'category':
                values = MOLECULAR_CATEGORIES[values[0]]['attrs']
            var_param_name = "var_class{}{}".format(str(mut_filtr_count),
                                                    '_{}'.format(param_suffix) if param_suffix else '')
            filter_string += '{}Variant_Classification {}IN UNNEST(@{})'.format(
                '' if not field_prefix else field_prefix, 'NOT ' if invert else '', var_param_name)
            var_query_param = ArrayQueryParameter(var_param_name, 'STRING', [{'value': x} for x in values])

        filter_set.append('({})'.format(filter_string))
        result['parameters'].append(gene_query_param)
        var_query_param and result['parameters'].append(var_query_param)

        mut_filtr_count += 1

    # Standard query filters
    for attr, values in list(other_filters.items()):
        if type(values) is not list:
            values = [values]

        parameter_type = None
        if type_schema and type_schema.get(attr, None):
            parameter_type = ('NUMERIC' if type_schema[attr] != 'STRING' else 'STRING')
        elif FIXED_TYPES.get(attr, None):
            parameter_type = FIXED_TYPES.get(attr)
        else:
            # If the values are arrays we assume the first value in the first array is indicative of all
            # other values (since we don't support multi-typed fields)
            type_check = values[0] if type(values[0]) is not list else values[0][0]
            parameter_type = (
                'STRING' if (
                        type(type_check) not in [int, float, complex] and re.compile(r'[^0-9\.,]', re.UNICODE).search(
                            type_check
                        )
                ) else 'NUMERIC'
            )

        filter_string = ''
        param_name = attr + '{}'.format('_{}'.format(param_suffix) if param_suffix else '')

        query_param = ScalarQueryParameter(param_name, parameter_type, None)

        if 'None' in values:
            values.remove('None')
            filter_string = "{}{} IS NULL".format('' if not field_prefix else field_prefix, attr)

        if len(values) > 0:
            if len(filter_string):
                filter_string += " OR "
            if len(values) == 1:
                # Scalar param
                query_param.value = values[0]
                if query_param.type_ == 'STRING':
                    if '%' in values[0] or case_insens:
                        filter_string += "LOWER({}{}) LIKE LOWER(@{})".format('' if not field_prefix else field_prefix,
                                                                              attr, param_name)
                    else:
                        filter_string += "{}{} = @{}".format('' if not field_prefix else field_prefix, attr,
                                                             param_name)
                elif query_param.type_ == 'INT64':
                    if attr.endswith('_gt') or attr.endswith('_gte'):
                        filter_string += "{}{} >{} @{}".format(
                            '' if not field_prefix else field_prefix, attr[:attr.rfind('_')],
                            '=' if attr.endswith('_gte') else '',
                            param_name
                        )
                    elif attr.endswith('_lt') or attr.endswith('_lte'):
                        filter_string += "{}{} <{} @{}".format(
                            '' if not field_prefix else field_prefix, attr[:attr.rfind('_')],
                            '=' if attr.endswith('_lte') else '',
                            param_name
                        )
                    else:
                        filter_string += "{}{} = @{}".format(
                            '' if not field_prefix else field_prefix, attr[:attr.rfind('_')],
                            param_name
                        )
            elif len(values) == 2 and attr.endswith('_btw'):
                param_name_1 = param_name + '_btw_1'
                param_name_2 = param_name + '_btw_2'
                filter_string += "{}{} BETWEEN @{} AND @{}".format(
                    '' if not field_prefix else field_prefix, attr[:attr.rfind('_')],
                    param_name_1,
                    param_name_2
                )
                query_param_1 = query_param
                query_param_2 = copy.deepcopy(query_param)
                query_param = [query_param_1, query_param_2, ]
                query_param_1.name = param_name_1
                query_param_1.value = values[0]
                query_param_2.name = param_name_2
                query_param_2.value = values[1]

            else:
                # Array param
                query_param = ArrayQueryParameter(param_name, parameter_type,
                                                  [{'value': x.lower() if parameter_type == 'STRING' else x} for x in
                                                   values])
                filter_string += "LOWER({}{}) IN UNNEST(@{})".format('' if not field_prefix else field_prefix, attr,
                                                                     param_name)

        if with_count_toggle:
            filter_string = "({}) OR @{}_filtering = 'not_filtering'".format(filter_string, param_name)
            result['count_params'][param_name] = ScalarQueryParameter(param_name + '_filtering', 'STRING', 'filtering')
            result['parameters'].append(result['count_params'][param_name])

        filter_set.append('({})'.format(filter_string))

        if type(query_param) is list:
            result['parameters'].extend(query_param)
        else:
            result['parameters'].append(query_param)

    result['filter_string'] = " {} ".format(comb_with).join(filter_set)

    return result


# Builds a BQ WHERE clause from a set of filters of the form:
# {
#     'field_name': [<value>,...]
# }
# Breaks out '<ATTR> IS NULL'
# 2+ values are converted to IN (<value>,...)
# Filters must already be pre-bucketed or formatted
# Use of LIKE is detected based on single-length value array and use of % in the value string
# Support special 'mutation' filter category
# Support for Greater/Less than (or equal to) via [gl]t[e]{0,1} in attr name,
#     eg. {"age_at_diagnosis_gte": [50,]}
# Support for BETWEEN via _btw in attr name, eg. ("wbc_at_diagnosis_btw": [800,1200]}
# Support for providing an explicit schema of the fields being searched
#
# TODO: add support for DATETIME eg 6/10/2010
def build_bq_where_clause(filters, join_with_space=False, comb_with='AND', field_prefix=None,
                          type_schema=None, encapsulated=True, continuous_numerics=None, case_insens=True,
                          value_op='OR'):
    global_value_op = value_op
    join_str = ","
    if join_with_space:
        join_str = ", "

    if field_prefix and field_prefix[-1] != ".":
        field_prefix += "."
    else:
        field_prefix = ""

    filter_set = []
    mutation_filters = {}
    other_filters = {}
    continuous_numerics = continuous_numerics or []

    # Split mutation filters into their own set, because of repeat use of the same attrs
    for attr in filters:
        if 'MUT:' in attr:
            mutation_filters[attr] = filters[attr]
        else:
            other_filters[attr] = filters[attr]

    mut_filtr_count = 1
    # 'Mutation' filters, special category for MUT: type filters
    for attr, values in list(mutation_filters.items()):
        if type(values) is not list:
            values = [values]
        gene = attr.split(':')[2]
        filter_type = attr.split(':')[-1].lower()
        invert = bool(attr.split(':')[3] == 'NOT')
        filter_string = '{}Hugo_Symbol = {} AND '.format('' if not field_prefix else field_prefix, gene)

        if filter_type == 'category' and values[0].lower() == 'any':
            filter_string += '{}Variant_Classification IS NOT NULL'.format('' if not field_prefix else field_prefix)
        else:
            if filter_type == 'category':
                values = MOLECULAR_CATEGORIES[values[0]]['attrs']
            filter_string += '{}Variant_Classification {}IN ({})'.format(
                '' if not field_prefix else field_prefix,
                'NOT ' if invert else '',
                join_str.join(["'{}'".format(x) for x in values])
            )

        filter_set.append('({})'.format(filter_string))

        mut_filtr_count += 1

    # Standard query filters
    for attr, values in list(other_filters.items()):
        is_btw = re.search('_e?btwe?', attr.lower()) is not None
        attr_name = attr[:attr.rfind('_')] if re.search('_[gl]te?|_e?btwe?', attr) else attr
        value_op = global_value_op
        encapsulate = encapsulated
        if type(values) is dict and 'values' in values:
            value_op = values.get('op', global_value_op)
            values = values['values']
            encapsulate = True if value_op == 'AND' else encapsulate

        # We require our attributes to be value lists
        if type(values) is not list:
            values = [values]
        # However, *only* ranged numerics can be a list of lists; all others must be a single list
        else:
            if type(values[0]) is list and not is_btw and attr not in continuous_numerics:
                values = [y for x in values for y in x]

        if (type_schema and type_schema.get(attr, None)):
            parameter_type = ('NUMERIC' if type_schema[attr] != 'STRING' else 'STRING')
        elif FIXED_TYPES.get(attr, None):
            parameter_type = FIXED_TYPES.get(attr)
        else:
            # If the values are arrays we assume the first value in the first array is indicative of all
            # other values (since we don't support multi-typed fields)
            type_check = values[0] if type(values[0]) is not list else values[0][0]
            parameter_type = (
                'STRING' if (
                    type(type_check) not in [int, float, complex] and re.compile(r'[^0-9\.,]', re.UNICODE).search(type_check)
                ) else 'NUMERIC'
            )

        filter_string = ''

        if 'None' in values:
            values.remove('None')
            filter_string = "{}{} IS NULL".format('' if not field_prefix else field_prefix, attr_name)

        if len(values) > 0:
            if len(filter_string):
                filter_string += " OR "
            if len(values) == 1 and not is_btw:
                # Scalar param
                if parameter_type == 'STRING':
                    if '%' in values[0] or case_insens:
                        filter_string += "LOWER({}{}) LIKE LOWER('{}')".format(
                            '' if not field_prefix else field_prefix, attr_name, values[0])
                    else:
                        filter_string += "{}{} = '{}'".format(
                            '' if not field_prefix else field_prefix, attr_name, values[0])
                elif parameter_type == 'NUMERIC':
                    if attr.endswith('_gt') or attr.endswith('_gte'):
                        filter_string += "{}{} >{} {}".format(
                            '' if not field_prefix else field_prefix, attr_name,
                            '=' if attr.endswith('_gte') else '',
                            values[0]
                        )
                    elif attr.endswith('_lt') or attr.endswith('_lte'):
                        filter_string += "{}{} <{} {}".format(
                            '' if not field_prefix else field_prefix, attr_name,
                            '=' if attr.endswith('_lte') else '',
                            values[0]
                        )
                    else:
                        filter_string += "{}{} = {}".format(
                            '' if not field_prefix else field_prefix, attr_name,
                            values[0]
                        )
            # Occasionally attributes may come in without the appropriate _e?btwe? suffix; we account for that here
            # by checking for the proper attr_name in the optional continuous_numerics list
            elif is_btw or attr_name in continuous_numerics:
                # Check for a single array of two and if we find it, convert it to an array containing
                # a 2-member array
                if len(values) == 2 and type(values[0]) is not list:
                    values = [values]
                else:
                    # confirm an array of arrays all contain paired values
                    all_pairs = True
                    for x in values:
                        if len(x) != 2:
                            all_pairs = False
                    if not all_pairs:
                        logger.error("[ERROR] While parsing attribute {}, calculated to be a numeric range filter, found an unparseable value:".format(attr_name))
                        logger.error("[ERROR] {}".format(values))
                        continue
                btw_filter_strings = []
                for btws in values:
                    if attr.endswith('_btw'):
                        ops =["{}{} > {}".format(
                            '' if not field_prefix else field_prefix, attr_name,
                            btws[0]
                        )]
                        # filter_string += " OR ".join(btw_filter_strings)
                        ops.append("{}{} < {}".format(
                            '' if not field_prefix else field_prefix, attr_name,
                            btws[1]
                        ))
                        btw_filter_strings.append(
                            " AND ".join(ops)
                        )
                    elif attr.endswith('_ebtw'):
                        ops =["{}{} >= {}".format(
                            '' if not field_prefix else field_prefix, attr_name,
                            btws[0]
                        )]
                        # filter_string += " OR ".join(btw_filter_strings)
                        ops.append("{}{} < {}".format(
                            '' if not field_prefix else field_prefix, attr_name,
                            btws[1]
                        ))
                        btw_filter_strings.append(
                            " AND ".join(ops)
                        )
                    elif attr.endswith('_btwe'):
                        ops =["{}{} > {}".format(
                            '' if not field_prefix else field_prefix, attr_name,
                            btws[0]
                        )]
                        # filter_string += " OR ".join(btw_filter_strings)
                        ops.append("{}{} <= {}".format(
                            '' if not field_prefix else field_prefix, attr_name,
                            btws[1]
                        ))
                        btw_filter_strings.append(
                            " AND ".join(ops)
                        )
                    else: # attr.endswith('_ebtwe'):
                        btw_filter_strings.append("{}{} BETWEEN {} AND {}".format(
                            '' if not field_prefix else field_prefix, attr_name,
                            btws[0],
                            btws[1]
                        ))
                        # filter_string += " OR ".join(btw_filter_strings)

                filter_string += " OR ".join(btw_filter_strings)
            else:
                if value_op == 'AND':
                    val_scalars = ["{}{} = {}".format(field_prefix or '', attr_name, "'{}'".format(x) if parameter_type == "STRING" else x) for x in values]
                    filter_string += " {} ".format(value_op).join(val_scalars)
                else:
                    val_list = join_str.join(
                        ["'{}'".format(x) for x in values]
                    ) if parameter_type == "STRING" else join_str.join(values)
                    filter_string += "{}{} IN ({})".format('' if not field_prefix else field_prefix, attr_name, val_list)

        filter_set.append('{}{}{}'.format("(" if encapsulate else "", filter_string, ")" if encapsulate else ""))

    return " {} ".format(comb_with).join(filter_set)
