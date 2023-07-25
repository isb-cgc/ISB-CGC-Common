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

"""
Helper methods for fetching, curating, and managing cohort metadata
"""
from __future__ import division
from django.conf import settings
from past.builtins import basestring
import logging
import sys

debug = settings.DEBUG # RO global for this file

logger = logging.getLogger('main_logger')


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

def sql_simple_number_by_200(value, field):
    if debug: logger.debug('[DEBUG] Called ' + sys._getframe().f_code.co_name)
    result = ''

    if not isinstance(value, list):
        value = [value]

    first = True
    for val in value:
        if first:
            first = False
        else:
            result += ' or'
        if str(val) == 'None':
            result += (' (%s IS NULL)' % field)
        elif str(val) == '0 to 200':
            result += (' (%s <= 200)' % field)
        elif str(val) == '200.01 to 400':
            result += (' (%s > 200 and %s <= 400)' % (field, field,))
        elif str(val) == '400.01 to 600':
            result += (' (%s > 400 and %s <= 600)' % (field, field,))
        elif str(val) == '600.01 to 800':
            result += (' (%s > 600 and %s <= 800)' % (field, field,))
        elif str(val) == '800.01 to 1000':
            result += (' (%s > 800 and %s <= 1000)' % (field, field,))
        elif str(val) == '1000.01 to 1200':
            result += (' (%s > 1000 and %s <= 1200)' % (field, field,))
        elif str(val) == '1200.01 to 1400':
            result += (' (%s > 1200 and %s <= 1400)' % (field, field,))
        elif str(val) == '1400.01+':
            result += (' (%s > 1400)' % (field,))

    return result


def sql_simple_days_by_ranges(value, field):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = ''

    if not isinstance(value, list):
        value = [value]

    first = True
    for val in value:
        if first:
            first = False
        else:
            result += ' or'

        if str(val) == 'None':
            result += (' %s IS NULL' % field)
        elif str(val) == '-30000 to -35000':
            result += (' (%s >= -35000 and %s <= -30001)' % (field, field,))
        elif str(val) == '-25001 to -30000':
            result += (' (%s >= -30000 and %s <= -25001)' % (field, field,))
        elif str(val) == '-20001 to -25000':
             result += (' (%s >= -25000 and %s <= -20001)' % (field, field,))
        elif str(val) == '-15001 to -20000':
             result += (' (%s >= -20000 and %s <= -15001)' % (field, field,))
        elif str(val) == '-10001 to -15000':
             result += (' (%s >= -15000 and %s <= -10001)' % (field, field,))
        elif str(val) == '-5001 to -10000':
             result += (' (%s >= -10000 and %s <= -5001)' % (field, field,))
        elif str(val) == '0 to -5000':
             result += (' (%s >= -5000 and %s <= 0)' % (field, field,))
        elif str(val) == '1 to 500':
            result += (' (%s <= 500)' % field)
        elif str(val) == '501 to 1000':
            result += (' (%s >= 501 and %s <= 1000)' % (field, field,))
        elif str(val) == '1001 to 1500':
             result += (' (%s >= 1001 and %s <= 1500)' % (field, field,))
        elif str(val) == '1501 to 2000':
             result += (' (%s >= 1501 and %s <= 2000)' % (field, field,))
        elif str(val) == '2001 to 2500':
             result += (' (%s >= 2001 and %s <= 2500)' % (field, field,))
        elif str(val) == '2501 to 3000':
             result += (' (%s >= 2501 and %s <= 3000)' % (field, field,))
        elif str(val) == '3001 to 3500':
             result += (' (%s >= 3001 and %s <= 3500)' % (field, field,))
        elif str(val) == '3501 to 4000':
             result += (' (%s >= 3501 and %s <= 4000)' % (field, field,))
        elif str(val) == '4001 to 4500':
             result += (' (%s >= 4001 and %s <= 4500)' % (field, field,))
        elif str(val) == '4501 to 5000':
             result += (' (%s >= 4501 and %s <= 5000)' % (field, field,))
        elif str(val) == '5001 to 5500':
             result += (' (%s >= 5001 and %s <= 5500)' % (field, field,))
        elif str(val) == '5501 to 6000':
             result += (' (%s >= 5501 and %s <= 6000)' % (field, field,))

    return result


def sql_year_by_ranges(value):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = ''

    if not isinstance(value, list):
        value = [value]

    first = True
    for val in value:
        if first:
            first = False
        else:
            result += ' or'

        if str(val) == 'None':
            result += ' year_of_diagnosis IS NULL'
        elif str(val) == '1976 to 1980':
            result += ' (year_of_diagnosis <= 1980)'
        elif str(val) == '1981 to 1985':
            result += ' (year_of_diagnosis >= 1981 and year_of_diagnosis <= 1985)'
        elif str(val) == '1986 to 1990':
            result += ' (year_of_diagnosis >= 1986 and year_of_diagnosis <= 1990)'
        elif str(val) == '1991 to 1995':
            result += ' (year_of_diagnosis >= 1991 and year_of_diagnosis <= 1995)'
        elif str(val) == '1996 to 2000':
            result += ' (year_of_diagnosis >= 1996 and year_of_diagnosis <= 2000)'
        elif str(val) == '2001 to 2005':
            result += ' (year_of_diagnosis >= 2001 and year_of_diagnosis <= 2005)'
        elif str(val) == '2006 to 2010':
            result += ' (year_of_diagnosis >= 2006 and year_of_diagnosis <= 2010)'
        elif str(val) == '2011 to 2015':
            result += ' (year_of_diagnosis >= 2011 and year_of_diagnosis <= 2015)'

    return result


def sql_bmi_by_ranges(value):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    result = ''
    if not isinstance(value, list):
        value = [value]

    first = True

    for val in value:
        if first:
            first = False
        else:
            result += ' or'

        if str(val) == 'None':
            result += ' bmi IS NULL'
        if str(val) == 'underweight':
            result += ' (bmi < 18.5)'
        elif str(val) == 'normal weight':
            result += ' (bmi >= 18.5 and bmi <= 24.9)'
        elif str(val) == 'overweight':
            result += ' (bmi > 24.9 and bmi <= 29.9)'
        elif str(val) == 'obese':
            result += ' (bmi > 29.9)'

    return result


def sql_age_by_ranges(value, bin_by_five=False):
    if debug: logger.debug('[DEBUG] Called '+sys._getframe().f_code.co_name)
    result = ''
    if not isinstance(value, list):
       value = [value]

    first = True
    for val in value:
        if first:
            first = False
        else:
            result += ' or'

        if str(val) == 'None':
            result += ' age_at_diagnosis IS NULL'
        else:
            if not bin_by_five:
                if str(val) == '10 to 39':
                    result += ' (age_at_diagnosis >= 10 and age_at_diagnosis < 40)'
                elif str(val) == '40 to 49':
                    result += ' (age_at_diagnosis >= 40 and age_at_diagnosis < 50)'
                elif str(val) == '50 to 59':
                    result += ' (age_at_diagnosis >= 50 and age_at_diagnosis < 60)'
                elif str(val) == '60 to 69':
                    result += ' (age_at_diagnosis >= 60 and age_at_diagnosis < 70)'
                elif str(val) == '70 to 79':
                    result += ' (age_at_diagnosis >= 70 and age_at_diagnosis < 80)'
                elif str(val).lower() == 'over 80':
                    result += ' (age_at_diagnosis >= 80)'
            else:
                if str(val) == '0 to 4':
                    result += ' (age_at_diagnosis >= 0 and age_at_diagnosis < 5)'
                elif str(val) == '5 to 9':
                    result += ' (age_at_diagnosis >= 5 and age_at_diagnosis < 10)'
                elif str(val) == '10 to 14':
                    result += ' (age_at_diagnosis >= 10 and age_at_diagnosis < 15)'
                elif str(val) == '15 to 19':
                    result += ' (age_at_diagnosis >= 15 and age_at_diagnosis < 20)'
                elif str(val) == '20 to 24':
                    result += ' (age_at_diagnosis >= 20 and age_at_diagnosis < 25)'
                elif str(val) == '25 to 29':
                    result += ' (age_at_diagnosis >= 25 and age_at_diagnosis < 30)'
                elif str(val) == '30 to 34':
                    result += ' (age_at_diagnosis >= 30 and age_at_diagnosis < 35)'
                elif str(val) == '35 to 39':
                    result += ' (age_at_diagnosis >= 35 and age_at_diagnosis < 40)'
                elif str(val).lower() == 'over 40':
                    result += ' (age_at_diagnosis >= 40)'

    return result
