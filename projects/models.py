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

import time
from builtins import object
import operator
import re
from django.db import models
from django.contrib.auth.models import User
from django.db.models import Q, Prefetch
from functools import reduce
import logging

logger = logging.getLogger(__name__)


class ProgramQuerySet(models.QuerySet):
    def get_projects(self):
        return Project.objects.select_related('program').filter(program__in=self.all())

    def name_id_map(self):
        id_map = {x.name: x.id for x in self}
        return id_map

    def get_data_sources(self, versions=None, data_type=None, source_type=None):
        sources = None
        q_obj = Q()
        if versions:
            q_obj &= Q(version__in=versions)
        if source_type:
            q_obj &= Q(source_type=source_type)
        ds_q_obj = Q()
        if data_type:
            if type(data_type) == list:
                ds_q_obj = Q(data_type__in=data_type)
                q_obj &= Q(datasettypes__data_type__in=data_type)
            else:
                ds_q_obj = Q(data_type=data_type)
                q_obj &= Q(datasettypes__data_type=data_type)

        for prog in self.all():
            sources = prog.datasource_set.prefetch_related(Prefetch(
                'datasettypes',
                queryset=DataSetType.objects.filter(ds_q_obj)
            )).filter(q_obj) if not sources else sources | prog.datasource_set.prefetch_related(Prefetch(
                'datasettypes',
                queryset=DataSetType.objects.filter(ds_q_obj)
            )).filter(q_obj)
        return sources.distinct()

    def get_prog_attr(self, filters=None):
        attrs = None
        filters = filters or Q()
        for prog in self.all():
            attrs = attrs | prog.attribute_set.filter(filters) if attrs else prog.attribute_set.filter(filters)
        return attrs.distinct()

    #
    # returns a dictionary of comprehensive information mapping attributes to this set of programs:
    #
    # {
    #   'list': [<String>, ...],
    #   'ids': [<Integer>, ...],
    #   'sources': {
    #      <data source database ID>: {
    #         'list': [<String>, ...],
    #         'attrs': [<Attribute>, ...],
    #         'id': <Integer>,
    #         'name': <String>,
    #         'data_sets': [<DataSetType>, ...],
    #         'count_col': <Integer>
    #      }
    #   }
    #
    def get_source_attrs(self, for_ui=None, for_faceting=True, by_source=True, named_set=None, with_set_map=False, active_only=False):
        start = time.time()
        # Simple string list of attribute names (warning: will not properly resolve for collision)
        attrs = { 'list': None, 'ids': None }
        # Full source-ID dictionary of attributes
        if by_source:
            attrs['sources'] = {}
        if with_set_map:
            attrs['set_map'] = {}

        q_objects = Q()
        if for_ui is not None:
            q_objects &= Q(default_ui_display=for_ui)
        if named_set:
            q_objects &= Q(name__in=named_set)
        if active_only:
            q_objects &= Q(active=True)
        if for_faceting:
            q_objects &= (Q(data_type=Attribute.CATEGORICAL) | Q(data_type=Attribute.CATEGORICAL_NUMERIC) | Q(id__in=Attribute_Ranges.objects.filter(
                    attribute__in=ds.attribute_set.all().filter(data_type=Attribute.CONTINUOUS_NUMERIC)
                ).values_list('attribute__id', flat=True)))

        sources = self.all().get_data_sources()
        prog_attr = self.get_prog_attr(q_objects)

        for ds in sources:

            attr_set = ds.attribute_set.filter(q_objects).intersect(prog_attr)

            if by_source:
                attrs['sources'][ds.id] = {
                    'list': list(set(attr_set.values_list('name', flat=True))),
                    'attrs': attr_set.distinct(),
                    'id': ds.id,
                    'name': ds.name,
                    'count_col': ds.count_col
                }

            if not attrs['list']:
                attrs['list'] = list(attr_set.values_list('name', flat=True))
            else:
                attrs['list'].extend(list(attr_set.values_list('name', flat=True)))
            if not attrs['ids']:
                attrs['ids'] = list(attr_set.values_list('id', flat=True))
            else:
                attrs['ids'].extend(list(attr_set.values_list('id', flat=True)))

        attrs['list'] = attrs['list'] and list(set(attrs['list']))
        attrs['ids'] = attrs['ids'] and list(set(attrs['ids']))
        stop = time.time()
        logger.debug("[STATUS] Time to build source attribute sets: {}".format(str(stop-start)))

        return attrs


class ProgramManager(models.Manager):
    def get_queryset(self):
        return ProgramQuerySet(self.model, using=self._db)

    def search(self, search_terms):
        terms = [term.strip() for term in search_terms.split()]
        q_objects = []
        for term in terms:
            q_objects.append(Q(name__icontains=term))

        # Start with a bare QuerySet
        qs = self.get_queryset()

        # Use operator's or_ to string together all of your Q objects.
        return qs.filter(reduce(operator.and_, [reduce(operator.or_, q_objects), Q(active=True)]))


class Program(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, null=True)
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    objects = ProgramManager()
    is_public = models.BooleanField(default=False)

    def get_data_sources(self, data_type=None, source_type=None, active=True, versions=None):
        q_objects = Q()
        q_obj_ds = Q()
        if active is not None:
            q_objects &= Q(version__active=active)
        if versions is not None:
            q_objects &= Q(version__in=versions)
        if data_type:
            if type(data_type) is list:
                q_obj_ds &= Q(data_type__in=data_type)
                q_objects &= Q(datasettypes__data_type__in=data_type)
            else:
                q_obj_ds &= Q(data_type=data_type)
                q_objects &= Q(datasettypes__data_type=data_type)
        if source_type:
            q_objects &= Q(source_type=source_type)

        return self.datasource_set.select_related('version').prefetch_related(Prefetch(
            'datasettypes',
            queryset=DataSetType.objects.filter(q_obj_ds)
        )).filter(q_objects)

    def get_source_attrs(self, for_ui=None, data_type=None, source_type=None, active=True, versions=None, for_faceting=True,
                  by_source=True, named_set=None, with_set_map=False, active_only=False):
        start = time.time()
        # Simple string list of attribute names (warning: will not properly resolve for collision)
        attrs = { 'list': None, 'ids': None }
        # Full source-ID dictionary of attributes
        if by_source:
            attrs['sources'] = {}
        if with_set_map:
            attrs['set_map'] = {}

        q_objects = Q()
        if for_ui is not None:
            q_objects &= Q(default_ui_display=for_ui)
        if named_set:
            q_objects &= Q(name__in=named_set)
        if active_only:
            q_objects &= Q(active=True)
        if for_faceting:
            q_objects &= (Q(data_type=Attribute.CATEGORICAL) | Q(data_type=Attribute.CATEGORICAL_NUMERIC) | Q(id__in=Attribute_Ranges.objects.filter(
                    attribute__in=self.attribute_set.filter(data_type=Attribute.CONTINUOUS_NUMERIC)
                ).values_list('attribute__id', flat=True)))

        sources = self.get_data_sources(data_type=data_type, source_type=source_type, active=active, versions=versions)
        prog_attr = self.attribute_set.filter(q_objects)

        for ds in sources:

            attr_set = ds.attribute_set.filter(q_objects) & prog_attr

            if by_source:
                attrs['sources'][ds.id] = {
                    'list': list(set(attr_set.values_list('name', flat=True))),
                    'attrs': attr_set.distinct(),
                    'id': ds.id,
                    'name': ds.name,
                    'count_col': ds.count_col
                }

            if not attrs['list']:
                attrs['list'] = list(attr_set.values_list('name', flat=True))
            else:
                attrs['list'].extend(list(attr_set.values_list('name', flat=True)))
            if not attrs['ids']:
                attrs['ids'] = list(attr_set.values_list('id', flat=True))
            else:
                attrs['ids'].extend(list(attr_set.values_list('id', flat=True)))

        attrs['list'] = attrs['list'] and list(set(attrs['list']))
        attrs['ids'] = attrs['ids'] and list(set(attrs['ids']))
        stop = time.time()
        logger.debug("[STATUS] Time to build source attribute sets: {}".format(str(stop-start)))

        return attrs

    def get_attrs(self, source_type, for_ui=True, data_type_list=None, for_faceting=True, versions=None, with_node=False):
        prog_attrs = {'attrs': {}, 'by_src': {}}
        datasources = self.get_data_sources(source_type=source_type, data_type=data_type_list, versions=versions)
        ds_attrs = datasources.get_source_attrs(for_ui=for_ui, for_faceting=for_faceting)
        q_objects = Q()
        if for_ui is not None:
            q_objects &= Q(default_ui_display=for_ui)
        if for_faceting:
            q_objects &= (Q(data_type=Attribute.CATEGORICAL) | Q(data_type=Attribute.CATEGORICAL_NUMERIC) | Q(
                id__in=Attribute_Ranges.objects.filter(
                    attribute__in=self.attribute_set.all().filter(data_type=Attribute.CONTINUOUS_NUMERIC)
                ).values_list('attribute__id', flat=True)))
        attrs = self.attribute_set.filter(q_objects)
        for attr in attrs:
            if attr.name in ds_attrs['list']:
                prog_attrs['attrs'][attr.name] = {
                    'id': attr.id,
                    'name': attr.name,
                    'displ_name': attr.display_name,
                    'values': {},
                    'type': attr.data_type,
                    'preformatted': bool(attr.preformatted_values),
                    'units': attr.units or None
                }

        if with_node:
            nodes = self.datanode_set.all()
            node_attrs = nodes.get_attrs(for_ui=for_ui, for_faceting=for_faceting, per_node=True)
            prog_attrs['by_node'] = {}
            for node in nodes:
                node_attrs_list = node_attrs[node.short_name].values_list('name', flat=True)
                prog_attrs['by_node'][node.short_name] = {x: prog_attrs['attrs'][x] for x in prog_attrs['attrs'] if x in node_attrs_list }

        for src in ds_attrs['sources']:
            prog_attrs['by_src'][src] = {
                'attrs': ds_attrs['sources'][src]['attrs'] & attrs.distinct(),
                'name': ds_attrs['sources'][src]['name']
             }

        return prog_attrs

    def get_projects(self, active=None):
        if active is not None:
            return self.project_set.filter(active=active)
        return self.project_set.filter()

    @classmethod
    def get_programs(cls, name=None, desc=None, public=True, active=None):
        params = {}
        if public is not None:
            params['is_public'] = public
        if name is not None:
            params['name__icontains'] = name
        if desc is not None:
            params['desc__icontains'] = desc
        if active is not None:
            params['active'] = active

        results = cls.objects.prefetch_related('project_set').filter(**params)

        return results

    @classmethod
    def get_public_programs(cls, name=None, desc=None, active=None):
        return cls.get_programs(name, desc, 1, active)

    @classmethod
    def get_private_programs(cls, name=None, desc=None, active=None):
        return cls.get_programs(name, desc, 0, active)

    def __str__(self):
        return self.name


class DataSetTypeQuerySet(models.QuerySet):
    def get_data_sources(self, is_active=None):
        sources = None
        q_obj = Q()
        if is_active is not None:
            q_obj = Q(version__active=is_active)
        dsts = self.all()
        for dst in dsts:
            if not sources:
                sources = dst.datasource_set.select_related('version').filter(q_obj)
            else:
                sources = sources | dst.datasource_set.select_related('version').filter(q_obj)
        return sources


class DataSetTypeManager(models.Manager):
    def get_queryset(self):
        return DataSetTypeQuerySet(self.model, using=self._db)


class DataSetType(models.Model):
    FILE_DATA = 'F'
    IMAGE_DATA = 'I'
    CLINICAL_DATA = 'C'
    BIOSPECIMEN_DATA = 'B'
    MUTATION_DATA = 'M'
    PROTEIN_DATA = 'P'
    FILE_TYPE_DATA = 'T'
    CASE_SET = 'D'
    FILE_AVAIL_SET = 'W'
    MUTATION_SET = 'N'
    FILE_LIST_SET = 'G'
    IMAGE_LIST_SET = 'J'
    DATA_TYPES = (
        (FILE_DATA, 'File Data'),
        (IMAGE_DATA, 'Image Data'),
        (CLINICAL_DATA, 'Clinical Data'),
        (BIOSPECIMEN_DATA, 'Biospecimen Data'),
        (MUTATION_DATA, 'Mutation Data'),
        (PROTEIN_DATA, 'Protein Data'),
        (FILE_TYPE_DATA, 'File Type Data')
    )
    SET_TYPES = (
        (CASE_SET, 'Case Set'),
        (FILE_AVAIL_SET, 'Available Files Set'),
        (MUTATION_SET, 'Mutation Data Set'),
        (FILE_LIST_SET, 'File List Set'),
        (IMAGE_LIST_SET, 'Images Set')
    )
    DATA_TYPE_DICT = {
        FILE_DATA: 'File Data',
        IMAGE_DATA: 'Image Data',
        CLINICAL_DATA: 'Clinical Data',
        BIOSPECIMEN_DATA: 'Biospecimen Data',
        MUTATION_DATA: 'Mutation Data',
        PROTEIN_DATA: 'Protein Data',
        FILE_TYPE_DATA: 'File Type Data'
    }
    # These terms should be simple terms with no spaces for dict key usage
    SET_TYPE_DICT = {
        CASE_SET: 'Case',
        FILE_AVAIL_SET: 'FileTypes',
        MUTATION_SET: 'Molec',
        FILE_LIST_SET: 'Files',
        IMAGE_LIST_SET: 'Images'
    }
    name = models.CharField(max_length=128, null=False, blank=False)
    display_name = models.CharField(max_length=256, null=True, blank=True)
    data_type = models.CharField(max_length=1, blank=False, null=False, choices=DATA_TYPES, default=CLINICAL_DATA)
    set_type = models.CharField(max_length=1, blank=False, null=False, choices=SET_TYPES, default=CASE_SET)
    objects = DataSetTypeManager()

    def __str__(self):
        return "{}: {}, {}".format(
            "{} ({})".format(self.display_name, self.name) if self.display_name is not None else self.name,
            self.SET_TYPE_DICT[self.set_type],
            self.DATA_TYPE_DICT[self.data_type]
        )


class CgcDataVersionQuerySet(models.QuerySet):

    # Return all the data sources corresponding to this queryset
    def get_data_sources(self, source_type=None, active=None, current=None, aggregate_level=None, data_type=None):
        sources = None
        cgcdvs = self.all()
        source_qs = Q()
        version_qs = Q()
        for cgcdv in cgcdvs:
            if active is not None:
                version_qs &= Q(active=active)
            if current is not None:
                version_qs &= Q(current=current)
            versions = cgcdv.dataversion_set.filter(version_qs).distinct()
            if not sources:
                sources = versions.get_data_sources()
            else:
                sources = sources | versions.get_data_sources()
        if source_type:
            source_qs &= Q(source_type=source_type)
        if data_type:
            source_qs &= Q(datasettypes__data_type=data_type)
        if aggregate_level:
            aggregate_level = aggregate_level if isinstance(aggregate_level, list) else [aggregate_level]
            source_qs &= Q(aggregate_level__in=aggregate_level)
        return sources.distinct().filter(source_qs)

    # Return all display strings in this queryset, either as a list (joined=False) or as a string (joined=True)
    def get_displays(self, joined=False, delimiter="; "):
        displays = []
        cgcdvs = self.all()
        for cgcdv in cgcdvs:
            displays.append(cgcdv.get_display())
        return displays if not joined else delimiter.join(displays)

    # Return all the DataVersions which have this CgcDataVersion
    def get_data_versions(self, active=None, current=None):
        cgcdvs = self.all()
        version_qs = Q()
        versions = None
        for cgcdv in cgcdvs:
            if active is not None:
                version_qs &= Q(active=active)
            if current is not None:
                version_qs &= Q(current=current)
            versions = cgcdv.dataversion_set.filter(version_qs).distinct()
        return versions


class CgcDataVersionManager(models.Manager):
    def get_queryset(self):
        return CgcDataVersionQuerySet(self.model, using=self._db)


class CgcDataVersion(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    name = models.CharField(max_length=128, null=False, blank=False)
    version_number = models.CharField(max_length=128, null=False, blank=False)
    version_uid = models.CharField(max_length=128, null=True)
    date_active = models.DateField(auto_now_add=True, null=False, blank=False)
    active = models.BooleanField(default=True, null=False, blank=False)
    objects = CgcDataVersionManager()

    def get_data_sources(self, active=None, source_type=None, aggregate_level=None):
        versions = self.dataversion_set.filter(active=active).distinct() if active is not None else self.dataversion_set.all().distinct()

        return versions.get_data_sources(source_type=source_type, aggregate_level=aggregate_level).distinct()

    def get_display(self):
        return self.__str__()

    def get_sub_version_displays(self, active=None, for_app=True):
        sub_versions = self.dataversion_set.filter(
            active=active).distinct() if active is not None else self.dataversion_set.all().distinct()
        return sub_versions.get_displays(for_app=for_app)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "{} Version {} {}".format(self.name, self.version_number, self.date_active)


class DataVersionQuerySet(models.QuerySet):
    def get_data_sources(self, source_type=None, aggregate_level=None, current=None):
        sources = None
        q_objs = Q()
        q_dv = Q()
        if aggregate_level:
            aggregate_level = aggregate_level if isinstance(aggregate_level, list) else [aggregate_level]
            q_objs &= Q(aggregate_level__in=aggregate_level)
        if source_type:
            q_objs &= Q(source_type=source_type)
        if current is not None:
            q_dv &= Q(active=True)
        dvs = self.filter(q_dv)
        for dv in dvs:
            if not sources:
                sources = dv.datasource_set.filter(q_objs)
            else:
                sources = sources | dv.datasource_set.filter(q_objs)
        return sources

    def get_active_cgc_versions(self):
        cgc_versions = None
        dvs = self.all()
        for dv in dvs:
            if not cgc_versions:
                cgc_versions = dv.cgc_versions.filter(active=True)
            else:
                cgc_versions = cgc_versions | dv.cgc_versions.filter(active=True)

        return cgc_versions

    def get_displays(self, with_active=False, for_app=False):
        return [dv.get_display(with_active, for_app) for dv in self.all()]


class DataVersionManager(models.Manager):
    def get_queryset(self):
        return DataVersionQuerySet(self.model, using=self._db)


# A data version represents a given release of data, eg. GDC Rel20 or IDC v15
class DataVersion(models.Model):
    version = models.CharField(max_length=64, null=False, blank=False)
    name = models.CharField(max_length=128, null=False, blank=False)
    active = models.BooleanField(default=True)
    build = models.CharField(max_length=16, null=True, blank=False)
    programs = models.ManyToManyField(Program)
    cgc_versions = models.ManyToManyField(CgcDataVersion)
    objects = DataVersionManager()

    def __str__(self, with_active=True, for_app=False):
        if for_app:
            return "{}{}".format(
                self.name,
                "" if not with_active else (": (Active)" if self.active else ": (Inactive)")
        )

        return "{}: {}{}".format(
            self.name,
            self.version,
            "" if not with_active else (" (Active)" if self.active else " (Inactive)")
        )

    def get_display(self, with_active=False, for_app=False):
        return self.__str__(with_active, for_app)


class DataSourceQuerySet(models.QuerySet):
    # simple dict version of the QuerySet
    def to_dicts(self):
        sources = self.all()
        return [{
            "id": ds.id,
            "name": ds.name,
            "versions": ["{}: {}".format(dv.name, dv.version) for dv in self.versions.all()],
            "type": ds.source_type,

        } for ds in sources]

    # Returns all versions to which these data sources belong
    # @active: optional, boolean
    def get_source_versions(self, active=None):
        versions = {}
        sources = self.all()
        for ds in sources:
            versions[ds.id] = ds.versions.filter(active=active) if active is not None else ds.versions.all()
        return versions

    def get_source_nodes(self):
        sources = self.all().prefetch_related('datanode_set')
        nodes = None
        for ds in sources:
            nodes = nodes | ds.datanode_set.all() if nodes else ds.datanode_set.all()
        return nodes.distinct()

    def get_source_programs(self):
        sources = self.all().prefetch_related('programs')
        progs = None
        for ds in sources:
            progs = progs | ds.programs.all() if progs else ds.programs.all()
        return progs.distinct()

    # Returns a dict of the datasources with their data set types as an array against their ID (pk)
    def get_source_data_types(self):
        data_types = {}
        sources = self.all()
        for ds in sources:
            data_set_types = ds.datasettypes.all()
            for data_set_type in data_set_types:
                if ds.id not in data_types:
                    data_types[ds.id] = []
                data_types[ds.id].append(data_set_type.data_type)
        return data_types

    # Returns a dict of the datasources with their data set types as an array against their ID (pk)
    def get_source_set_types(self, qualified_name=False):
        set_types = {}
        sources = self.all()
        for ds in sources:
            data_set_types = ds.datasettypes.all()
            for data_set_type in data_set_types:
                if ds.id not in set_types:
                    set_types[ds.id] = []
                set_types[ds.id].append(data_set_type.set_type)
        return set_types

    # Determines if a set of data sources contains any belonging to an inactive version
    def contains_inactive_versions(self):
        contains_inactive = False
        sources = self.all()
        for ds in sources:
            if len(ds.versions.filter(active=False)) > 0:
                contains_inactive = True
                break
        return contains_inactive

    #
    # returns a dictionary of comprehensive information mapping attributes to this set of data sources:
    #
    # {
    #   'list': [<String>, ...],
    #   'ids': [<Integer>, ...],
    #   'sources': {
    #      <data source database ID>: {
    #         'list': [<String>, ...],
    #         'attrs': [<Attribute>, ...],
    #         'id': <Integer>,
    #         'name': <String>,
    #         'data_sets': [<DataSetType>, ...],
    #         'count_col': <Integer>
    #      }
    #   }
    #
    def get_source_attrs(self, for_ui=None, for_faceting=True, by_source=True, named_set=None, active_only=False,
                         datasettypes=None):
        start = time.time()
        # Simple string list of attribute names (warning: will not properly resolve for collision)
        attrs = { 'list': None, 'ids': None, 'attrs': None }
        # Full source-ID dictionary of attributes
        if by_source:
            attrs['sources'] = {}

        sources = self.prefetch_related('datasettypes').filter(datasettypes__in=datasettypes) if datasettypes is not None else self.all()
        for ds in sources:
            q_objects = Q()
            if for_ui is not None:
                q_objects &= Q(default_ui_display=for_ui)
            if named_set:
                q_objects &= Q(name__in=named_set)
            if active_only:
                q_objects &= Q(active=True)
            if for_faceting:
                q_objects &= (Q(data_type=Attribute.CATEGORICAL) | Q(data_type=Attribute.CATEGORICAL_NUMERIC) | Q(id__in=Attribute_Ranges.objects.filter(
                        attribute__in=ds.attribute_set.all().filter(data_type=Attribute.CONTINUOUS_NUMERIC)
                    ).values_list('attribute__id', flat=True)))

            attr_set = ds.attribute_set.filter(q_objects)

            if by_source:
                attrs['sources'][ds.id] = {
                    'list': list(set(attr_set.values_list('name', flat=True))),
                    'attrs': attr_set.distinct(),
                    'id': ds.id,
                    'name': ds.name,
                    'data_sets': ds.datasettypes.all(),
                    'count_col': ds.count_col
                }

            attrs['attrs'] = attr_set if not attrs['attrs'] else attrs['attrs'] | attr_set

            if not attrs['list']:
                attrs['list'] = list(attr_set.values_list('name', flat=True))
            else:
                attrs['list'].extend(list(attr_set.values_list('name', flat=True)))
            if not attrs['ids']:
                attrs['ids'] = list(attr_set.values_list('id', flat=True))
            else:
                attrs['ids'].extend(list(attr_set.values_list('id', flat=True)))

        attrs['list'] = attrs['list'] and list(set(attrs['list']))
        attrs['ids'] = attrs['ids'] and list(set(attrs['ids']))
        attrs['attrs'] = attrs['attrs'].distinct() if attrs['attrs'] and len(attrs['attrs']) else None
        stop = time.time()
        logger.debug("[STATUS] Time to build source attribute sets: {}".format(str(stop-start)))

        return attrs


class DataSourceManager(models.Manager):
    def get_queryset(self):
        return DataSourceQuerySet(self.model, using=self._db)

    def search(self, search_terms):
        terms = [term.strip() for term in search_terms.split()]
        q_objects = []
        for term in terms:
            q_objects.append(Q(name__icontains=term))

        # Start with a bare QuerySet
        qs = self.get_queryset()

        # Use operator's or_ to string together all of your Q objects.
        return qs.filter(reduce(operator.and_, [reduce(operator.or_, q_objects), Q(active=True)]))


class DataSource(models.Model):
    QUERY = 'query'
    TERMS = 'terms'
    SOLR = 'S'
    BIGQUERY = 'B'
    SOURCE_TYPES = (
        (SOLR, "Solr Data Collection"),
        (BIGQUERY, "BigQuery Table")
    )
    SOURCE_TYPE_MAP = {
        SOLR: "Solr Data Collection",
        BIGQUERY: "BigQuery Table"
    }
    id = models.AutoField(primary_key=True, null=False, blank=False)
    name = models.CharField(max_length=128, null=False, blank=False, unique=True)
    version = models.ForeignKey(DataVersion, on_delete=models.CASCADE)
    programs = models.ManyToManyField(Program)
    source_type = models.CharField(max_length=1, null=False, blank=False, default=SOLR, choices=SOURCE_TYPES)
    datasettypes = models.ManyToManyField(DataSetType)
    count_col = models.CharField(max_length=128, null=False, blank=False, default="case_barcode")
    aggregate_level = models.CharField(max_length=128, null=False, blank=False, default="case_barcode")
    objects = DataSourceManager()

    def get_set_types(self):
        return [DataSetType.SET_TYPE_DICT[x] for x in self.datasettypes.all().values_list('set_type',flat=True)]

    def get_source_attr(self, for_ui=None, for_faceting=True, named_set=None, active=True, all=False):
        if all:
            attr_set = self.attribute_set.filter()
        else:
            q_objects = Q()

            if for_ui:
                q_objects &= Q(default_ui_display=True)
            if named_set:
                q_objects &= Q(name__in=named_set)
            if active is not None:
                q_objects &= Q(active=active)
            if for_faceting:
                q_objects &= (Q(id__in=Attribute_Ranges.objects.filter(
                    attribute__in=self.attribute_set.filter(data_type=Attribute.CONTINUOUS_NUMERIC)
                ).values_list('attribute', flat=True)) | Q(data_type=Attribute.CATEGORICAL))

            attr_set = self.attribute_set.filter(q_objects)

        return attr_set

    def __str__(self):
        return "{} ({}, {}) - {}".format(
            self.name,
            self.version.name,
            self.SOURCE_TYPE_MAP[self.source_type],
            self.datasettypes.all()
        )

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def get_facet_type(attr):
        if attr.data_type == Attribute.CONTINUOUS_NUMERIC and len(Attribute_Ranges.objects.filter(attribute=attr)) > 0:
            return DataSource.QUERY
        else:
            return DataSource.TERMS

    class Meta(object):
        unique_together = (("name", "version", "source_type"),)


# Simple mapping of two data sources and the columns which can be used to join data between them
class DataSourceJoin(models.Model):
    from_src = models.ForeignKey(DataSource, on_delete=models.CASCADE, related_name="from_data_source")
    from_src_col = models.CharField(max_length=64, null=False, blank=False)
    to_src = models.ForeignKey(DataSource, on_delete=models.CASCADE, related_name="to_data_source")
    to_src_col = models.CharField(max_length=64, null=False, blank=False)

    def get_col(self, source_name):
        if source_name == self.from_src.name:
            return self.from_src_col
        elif source_name == self.to_src.name:
            return self.to_src_col
        return None

    def __str__(self):
        return "DataSourceJoin: {}.{} on {}.{}".format(self.from_src.name, self.from_src_col, self.to_src.name, self.to_src_col)


class DataNodeQuerySet(models.QuerySet):
    def to_dicts(self):
        return [{
            "id": ds.id,
            "name": ds.name

        } for ds in self.select_related('version').all()]

    def get_data_sources(self, per_node=False):
        sources = None
        for dn in self.all():
            if per_node:
                sources = {} if not sources else sources
                sources[dn.id] = {
                    'name': dn.short_name,
                    'full_name': dn.name,
                    'sources': [{'name': x.name, 'source_type': DataSource.SOURCE_TYPE_MAP[x.source_type]} for x in dn.data_sources.all()]
                }
            else:
                sources = dn.data_sources.all() if not sources else sources | dn.data_sources.all()
        return sources

    def get_attrs(self, for_ui=True, for_faceting=True, per_node=True):
        node_attrs = None
        for dn in self.all():
            q_objects = Q()
            if for_ui is not None:
                q_objects &= Q(default_ui_display=for_ui)
            if for_faceting:
                q_objects &= (Q(data_type=Attribute.CATEGORICAL) | Q(data_type=Attribute.CATEGORICAL_NUMERIC) | Q(
                    id__in=Attribute_Ranges.objects.filter(
                        attribute__in=dn.attribute_set.all().filter(data_type=Attribute.CONTINUOUS_NUMERIC)
                    ).values_list('attribute__id', flat=True)))
            attrs = dn.attribute_set.filter(q_objects)
            if per_node:
                node_attrs = node_attrs or {}
                node_attrs[dn.short_name] = attrs.distinct()
            else:
                node_attrs = attrs if not node_attrs else attrs | node_attrs
        return node_attrs


class DataNodeManager(models.Manager):
    def get_queryset(self):
        return DataNodeQuerySet(self.model, using=self._db)


class DataNode(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    short_name = models.CharField(max_length=16)
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    data_sources = models.ManyToManyField(DataSource)
    programs = models.ManyToManyField(Program)
    objects = DataNodeManager()

    def __str__(self):
        return "{} - {}".format(self.short_name, self.name)


    @classmethod
    def get_node_programs(cls, data_types=None, is_active=None):
        by_node_list = []
        by_prog_list = []
        nodes = None
        programs = None

        if data_types or is_active is not None:
            q_obj = Q()
            if data_types:
                q_obj &= Q(data_type__in=data_types)
            data_sources = DataSetType.objects.filter(q_obj).get_data_sources(is_active)
            nodes = data_sources.get_source_nodes().prefetch_related('programs')
            programs = data_sources.get_source_programs().prefetch_related('datanode_set')
        else:
            nodes = cls.objects.filter(active=True).prefetch_related('programs')
            programs = Program.objects.all().prefetch_related('datanode_set')

        for node in nodes.order_by('short_name'):
            by_node_list.append({
                "id": node.id,
                "name": node.name,
                "description": node.description,
                "short_name": node.short_name,
                "programs": [{
                    "id": prog.id,
                    "name": prog.name,
                    "description": prog.description
                } for prog in node.programs.all().order_by('name')]
            })

        for program in programs.order_by('name'):
            by_prog_list.append({
                "id": program.id,
                "name": program.name,
                "description": program.description,
                "nodes": [{
                    "id": node.id,
                    "name": node.name,
                    "description": node.description,
                    "short_name": node.short_name
                } for node in program.datanode_set.all() if node in nodes],
                "node_list": ", ".join([node.short_name for node in program.datanode_set.all() if node in nodes])
            })

        return by_node_list, by_prog_list


class Project(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False) # Auto-generated numeric
    short_name = models.CharField(max_length=15, null=False, blank=False) # Eg. TCGA-BRCA
    name = models.CharField(max_length=255) # Eg. Framingham Heart Study
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    program = models.ForeignKey(Program, on_delete=models.CASCADE)
    is_public = models.BooleanField(default=False)

    def __str__(self):
        return "{} ({}), {}".format(self.short_name, self.name,
                                    "Public" if self.is_public else "Private (owner: {})".format(self.owner.email))

    class Meta(object):
        verbose_name_plural = "projects"


class AttributeQuerySet(models.QuerySet):

    def get_data_sources(self, versions=None, source_type=None, active=None, current=True, aggregate_level=None):
        q_objects = Q()
        if versions:
            q_objects &= Q(id__in=versions.get_data_sources(current=current, active=active))
        if source_type:
            q_objects &= Q(source_type=source_type)
        if aggregate_level:
            aggregate_level = aggregate_level if isinstance(aggregate_level, list) else [aggregate_level]
            q_objects &= Q(aggregate_level__in=aggregate_level)

        data_sources = None
        attrs = self.all()
        for attr in attrs:
            data_sources = attr.data_sources.filter(q_objects) if not data_sources else (data_sources|attr.data_sources.filter(q_objects))

        return data_sources.distinct() if data_sources else None

    def get_attr_ranges(self, as_dict=False):
        if as_dict:
            ranges = {}
            for range in Attribute_Ranges.objects.select_related('attribute').filter(attribute__in=self.all()):
                if range.attribute.id not in ranges:
                    ranges[range.attribute.id] = []
                ranges[range.attribute.id].append(range)
            return ranges
        return Attribute_Ranges.objects.select_related('attribute').filter(attribute__in=self.all())

    def get_facet_types(self):
        facet_types = {}
        attr_with_ranges = {x[0]: x[1] for x in Attribute_Ranges.objects.select_related('attribute').filter(
            attribute__in=self.all()).values_list('attribute__id','attribute__data_type')}
        for attr in self.all():
            facet_types[attr.id] = DataSource.QUERY if attr.data_type == Attribute.CONTINUOUS_NUMERIC and attr.id in attr_with_ranges else DataSource.TERMS
        return facet_types
    
    def get_display_values(self):
        return Attribute_Display_Values.objects.select_related('attribute').filter(attribute__in=self.all())

    def get_attr_set_types(self):
        return Attribute_Set_Type.objects.select_related('attribute', 'datasettype').filter(attribute__in=self.all())

    def get_attr_sets(self):
        sets = {}
        for set_type in Attribute_Set_Type.objects.select_related('attribute', 'datasettype').filter(attribute__in=self.all()):
            if set_type.attribute.name not in sets:
                sets[set_type.attribute.name] = []
            sets[set_type.attribute.name].append(set_type.datasettype.data_type)
        return sets


class AttributeManager(models.Manager):
    def get_queryset(self):
        return AttributeQuerySet(self.model, using=self._db)


# A field which is available in data sources. Attributes may be linked to numerous data sources.
class Attribute(models.Model):
    CONTINUOUS_NUMERIC = 'N'
    CATEGORICAL_NUMERIC = 'M'
    CATEGORICAL = 'C'
    TEXT = 'T'
    STRING = 'S'
    DATE = 'D'
    DATA_TYPES = (
        (CONTINUOUS_NUMERIC, 'Continuous Numeric'),
        (CATEGORICAL, 'Categorical String'),
        (CATEGORICAL_NUMERIC, 'Categorical Number'),
        (TEXT, 'Text'),
        (STRING, 'String'),
        (DATE, 'Date')
    )
    DATA_TYPE_MAP = {
        CONTINUOUS_NUMERIC: 'Continuous Numeric',
        CATEGORICAL: 'Categorical String',
        CATEGORICAL_NUMERIC: 'Categorical Number',
        TEXT: 'Text',
        STRING: 'String',
        DATE: 'Date'
    }
    id = models.AutoField(primary_key=True, null=False, blank=False)
    name = models.CharField(max_length=64, null=False, blank=False)
    display_name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    data_type = models.CharField(max_length=1, blank=False, null=False, choices=DATA_TYPES, default=CATEGORICAL)
    active = models.BooleanField(default=True)
    is_cross_collex = models.BooleanField(default=False)
    preformatted_values = models.BooleanField(default=False)
    default_ui_display = models.BooleanField(default=True)
    data_sources = models.ManyToManyField(DataSource)
    nodes = models.ManyToManyField(DataNode)
    programs = models.ManyToManyField(Program)
    units = models.CharField(max_length=256, blank=True, null=True)
    objects = AttributeManager()

    @classmethod
    def get_clean_attr_names(cls, names_list):
        names = [re.sub(r'_btw|_[lg]te?', '', x) for x in names_list]
        return names

    @classmethod
    def get_ranged_attrs(cls, as_list=True):
        ranged = cls.objects.filter(data_type=cls.CONTINUOUS_NUMERIC, active=True)
        if as_list:
            return list(ranged.values_list('name',flat=True))
        return ranged

    def get_display_values(self):
        display_vals = self.attribute_display_values_set.all()
        result = {}

        for val in display_vals:
            result[val.raw_value] = val.display_value

        return result

    def get_data_sources(self, source_type=None, all=False):
        q_obj = Q()
        if not all:
            q_obj &= Q(version__active=True)
        if source_type:
            q_obj &= Q(source_type=source_type)

        return self.data_sources.prefetch_related('version').filter(q_obj).values_list('name', flat=True)

    def get_programs(self):
        return self.programs.values_list('name', flat=True)

    def get_nodes(self):
        return self.nodes.values_list('short_name', flat=True)

    def get_ranges(self):
        return self.attribute_ranges_set.all()

    def __str__(self):
        return "{} ({}), Type: {}".format(
            self.name, self.display_name, self.data_type)


# This model allows for breaking Attributes up beyond the strict DataSource->DataSetType heirarchy,
# since an attribute might be found in a DataSource housing more than one set type.
class Attribute_Set_Type(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    datasettype = models.ForeignKey(DataSetType, null=False, blank=False, on_delete=models.CASCADE)

    class Meta(object):
        unique_together = (("datasettype", "attribute"),)


class Attribute_Display_ValuesQuerySet(models.QuerySet):
    def to_dict(self, index_by_id=True):
        dvals = {}
        for dv in self.all().select_related('attribute'):
            attr_i = dv.attribute.name
            if index_by_id:
                attr_i = dv.attribute.id
            if attr_i not in dvals:
                dvals[attr_i] = {}
            dvals[attr_i][dv.raw_value] = dv.display_value

        return dvals


class Attribute_Display_ValuesManager(models.Manager):
    def get_queryset(self):
        return Attribute_Display_ValuesQuerySet(self.model, using=self._db)


# Attributes with specific display value attributes can use this model to record them
class Attribute_Display_Values(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    raw_value = models.CharField(max_length=256, null=False, blank=False)
    display_value = models.CharField(max_length=256, null=False, blank=False)
    objects=Attribute_Display_ValuesManager()

    class Meta(object):
        unique_together = (("raw_value", "attribute"),)

    def __str__(self):
        return "{} - {}".format(self.raw_value, self.display_value)


# Attributes with tooltips for their values can use this model to record them
class Attribute_Tooltips(models.Model):
    id = models.AutoField(primary_key=True, null=False, blank=False)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    value = models.CharField(max_length=256, null=False, blank=False)
    tooltip = models.CharField(max_length=256, null=False, blank=False)

    class Meta(object):
        unique_together = (("value", "attribute"),)

    def __str__(self):
        return "{} - {}".format(self.value, self.display_value)


# Attributes which should have faceted counting performed in buckets of ranges can record those buckets
# using this class
class Attribute_Ranges(models.Model):
    FLOAT = 'F'
    INT = 'I'
    RANGE_TYPES = (
        (FLOAT, 'Float'),
        (INT, 'Integer')
    )
    id = models.AutoField(primary_key=True, null=False, blank=False)
    # The type determines what a ranging method will do to cast a numeric value onto first, last, and gap
    type = models.CharField(max_length=1, blank=False, null=False, choices=RANGE_TYPES, default=INT)
    attribute = models.ForeignKey(Attribute, null=False, blank=False, on_delete=models.CASCADE)
    # In any range with an lower value, use <= or >= rather than < or >
    include_lower = models.BooleanField(default=True)
    # In any range with an upper value, use <= or >= rather than < or >
    include_upper = models.BooleanField(default=False)
    # Include ranges for [* to first] and [last to *]
    unbounded = models.BooleanField(default=True)
    # The beginning and end of the range
    first = models.CharField(max_length=128, null=False, blank=False, default="10")
    last = models.CharField(max_length=128, null=False, blank=False, default="80")
    # Value to separate sequential buckets. If gap == 0, this can be assumed to be a single range bucket
    gap = models.CharField(max_length=128, null=False, blank=False, default="10")
    # Value to determine display in include upper/lower situations
    unit = models.CharField(max_length=128, null=False, blank=False, default="1")
    # Optional, for UI display purposes
    label = models.CharField(max_length=256, null=True, blank=True)

    def __str__(self):
        return "{}: {} to {} by {}".format(self.attribute.name, str(self.start), str(self.last), str(self.gap))
