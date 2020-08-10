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


# TODO: Convert to slider
def normalize_bmi(bmis):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    bmi_list = {'underweight': 0, 'normal weight': 0, 'overweight': 0, 'obese': 0, 'None': 0}
    for bmi, count in list(bmis.items()):
        if type(bmi) != dict:
            if bmi and bmi != 'None':
                fl_bmi = float(bmi)
                if fl_bmi < 18.5:
                    bmi_list['underweight'] += int(count)
                elif 18.5 <= fl_bmi <= 24.9:
                    bmi_list['normal weight'] += int(count)
                elif 25 <= fl_bmi <= 29.9:
                    bmi_list['overweight'] += int(count)
                elif fl_bmi >= 30:
                    bmi_list['obese'] += int(count)
            else:
                bmi_list['None'] += int(count)
    return bmi_list


# TODO: Convert to slider
def normalize_ages(ages,bin_by_five=False):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    new_age_list = None
    if bin_by_five:
        new_age_list = {'0 to 4': 0, '5 to 9': 0, '10 to 14': 0, '15 to 19': 0, '20 to 24': 0, '25 to 29': 0, '30 to 34':0, '35 to 39': 0, 'Over 40': 0, 'None': 0}
    else:
        new_age_list = {'10 to 39': 0, '40 to 49': 0, '50 to 59': 0, '60 to 69': 0, '70 to 79': 0, 'Over 80': 0, 'None': 0}
    for age, count in list(ages.items()):
        if type(age) != dict:
            if age and age != 'None':
                int_age = float(age)
                if bin_by_five:
                    if int_age < 5:
                        new_age_list['0 to 4'] += int(count)
                    elif int_age < 10:
                        new_age_list['5 to 9'] += int(count)
                    elif int_age < 15:
                        new_age_list['10 to 14'] += int(count)
                    elif int_age < 20:
                        new_age_list['15 to 19'] += int(count)
                    elif int_age < 25:
                        new_age_list['20 to 24'] += int(count)
                    elif int_age < 30:
                        new_age_list['25 to 29'] += int(count)
                    elif int_age < 35:
                        new_age_list['30 to 34'] += int(count)
                    elif int_age < 40:
                        new_age_list['35 to 39'] += int(count)
                    else:
                        new_age_list['Over 40'] += int(count)
                else:
                    if int_age < 40:
                        new_age_list['10 to 39'] += int(count)
                    elif int_age < 50:
                        new_age_list['40 to 49'] += int(count)
                    elif int_age < 60:
                        new_age_list['50 to 59'] += int(count)
                    elif int_age < 70:
                        new_age_list['60 to 69'] += int(count)
                    elif int_age < 80:
                        new_age_list['70 to 79'] += int(count)
                    else:
                        new_age_list['Over 80'] += int(count)
            else:
                new_age_list['None'] += int(count)
        else:
            logger.warn("[WARNING] Age was sent as a dict.")

    return new_age_list


# TODO: Convert to slider
def normalize_years(years):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    new_year_list = {'1976 to 1980': 0, '1981 to 1985': 0, '1986 to 1990': 0, '1991 to 1995': 0, '1996 to 2000': 0, '2001 to 2005': 0, '2006 to 2010': 0, '2011 to 2015': 0, 'None': 0}
    for year, count in list(years.items()):
        if type(year) != dict:
            if year and year != 'None':
                int_year = float(year)
                if int_year <= 1980:
                    new_year_list['1976 to 1980'] += int(count)
                elif int_year <= 1985:
                    new_year_list['1981 to 1985'] += int(count)
                elif int_year <= 1990:
                    new_year_list['1986 to 1990'] += int(count)
                elif int_year <= 1995:
                    new_year_list['1991 to 1995'] += int(count)
                elif int_year <= 2000:
                    new_year_list['1996 to 2000'] += int(count)
                elif int_year <= 2005:
                    new_year_list['2001 to 2005'] += int(count)
                elif int_year <= 2010:
                    new_year_list['2006 to 2010'] += int(count)
                elif int_year <= 2015:
                    new_year_list['2011 to 2015'] += int(count)
            else:
                new_year_list['None'] += int(count)

    return new_year_list


# TODO: Convert to slider
def normalize_simple_days(days):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    new_day_list = {'1 to 500': 0, '501 to 1000': 0, '1001 to 1500': 0, '1501 to 2000': 0, '2001 to 2500': 0,
                    '2501 to 3000': 0, '3001 to 3500': 0, '3501 to 4000': 0, '4001 to 4500': 0, '4501 to 5000': 0,
                    '5001 to 5500': 0, '5501 to 6000': 0, 'None': 0}
    for day, count in list(days.items()):
        if type(day) != dict:
            if day and day != 'None':
                int_day = float(day)
                if int_day <= 500:
                    new_day_list['1 to 500'] += int(count)
                elif int_day <= 1000:
                    new_day_list['501 to 1000'] += int(count)
                elif int_day <= 1500:
                    new_day_list['1001 to 1500'] += int(count)
                elif int_day <= 2000:
                    new_day_list['1501 to 2000'] += int(count)
                elif int_day <= 2500:
                    new_day_list['2001 to 2500'] += int(count)
                elif int_day <= 3000:
                    new_day_list['2501 to 3000'] += int(count)
                elif int_day <= 3500:
                    new_day_list['3001 to 3500'] += int(count)
                elif int_day <= 4000:
                    new_day_list['3501 to 4000'] += int(count)
                elif int_day <= 4500:
                    new_day_list['4001 to 4500'] += int(count)
                elif int_day <= 5000:
                    new_day_list['4501 to 5000'] += int(count)
                elif int_day <= 5500:
                    new_day_list['5001 to 5500'] += int(count)
                elif int_day <= 6000:
                    new_day_list['5501 to 6000'] += int(count)
            else:
                new_day_list['None'] += int(count)

    return new_day_list


# TODO: Convert to slider
def normalize_negative_days(days):
    if debug: logger.debug('Called ' + sys._getframe().f_code.co_name)
    new_day_list = {'0 to -5000': 0, '-5001 to -10000': 0, '-10001 to -15000': 0, '-15001 to -20000': 0, '-20001 to -25000': 0,
                    '-25001 to -30000': 0, '-30001 to -35000': 0, 'None': 0}
    for day, count in list(days.items()):
        if type(day) != dict:
            if day and day != 'None':
                int_day = float(day)
                if int_day >= -5000:
                    new_day_list['0 to -5000'] += int(count)
                elif int_day >= -10000:
                    new_day_list['-5001 to -10000'] += int(count)
                elif int_day >= -15000:
                    new_day_list['-10001 to -15000'] += int(count)
                elif int_day >= -20000:
                    new_day_list['-15001 to -20000'] += int(count)
                elif int_day >= -25000:
                    new_day_list['-20001 to -25000'] += int(count)
                elif int_day >= -30000:
                    new_day_list['-25001 to 30000'] += int(count)
                elif int_day >= -35000:
                    new_day_list['-30001 to -35000'] += int(count)
            else:
                new_day_list['None'] += int(count)

    return new_day_list


# TODO: Convert to slider
def normalize_by_200(values):
    if debug: logger.debug('Called '+sys._getframe().f_code.co_name)
    new_value_list = {'0 to 200': 0, '200.01 to 400': 0, '400.01 to 600': 0, '600.01 to 800': 0, '800.01 to 1000': 0,
                    '1000.01 to 1200': 0, '1200.01 to 1400': 0, '1400.01+': 0, 'None': 0}
    for value, count in list(values.items()):
        if type(value) != dict:
            if value and value != 'None':
                int_value = float(value)
                if int_value <= 200:
                    new_value_list['0 to 200'] += int(count)
                elif int_value <= 400:
                    new_value_list['200.01 to 400'] += int(count)
                elif int_value <= 600:
                    new_value_list['400.01 to 600'] += int(count)
                elif int_value <= 800:
                    new_value_list['600.01 to 800'] += int(count)
                elif int_value <= 1000:
                    new_value_list['800.01 to 1000'] += int(count)
                elif int_value <= 1200:
                    new_value_list['1000.01 to 1200'] += int(count)
                elif int_value <= 1400:
                    new_value_list['1200.01 to 1400'] += int(count)
                elif int_value > 1400:
                    new_value_list['1400.01+'] += int(count)
            else:
                new_value_list['None'] += int(count)

    return new_value_list


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
