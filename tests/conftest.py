#!/usr/bin/env python3

from contextlib import contextmanager
import csv
import os.path
import pkg_resources
import zipfile
from zipimport import zipimporter

import polyunite


def open_fixture(filename):
    name, _ = filename.split('.')
    path = os.path.join(os.path.dirname(__file__), 'fixtures', f'{name}.zip')
    return zipimporter(path).get_data(filename)


def seen():
    fixtures = open_fixture('engine_families.csv')
    for row in csv.DictReader(fixtures.decode('utf-8').splitlines()):
        yield row['engine'], row['classification']


def format_match(engine, label, vr):
    return ' | '.join((
        '{:<10}',
        '{:1}',
        '{:<10.10}',
        '{:<9.9}',
        '{:<10.10}',
        '{:55}',
        '{:>15.15}',
        '{}',
    )).format(
        engine,
        vr.is_heuristic and 'H' or '',
        vr.operating_system or '',
        vr.language or '',
        vr.macro or '',
        ', '.join(vr.labels),
        vr.name,
        vr.colorize(),
    )


def match_iter(only=None):
    missing = set()
    errors = []
    for engine, label in seen():
        if only and engine not in only:
            continue

        try:
            yield (engine, label, polyunite.parse(engine, label))
        except polyunite.errors.MatchError as e:
            errors.append((engine, label, e))
        except polyunite.errors.RegistryKeyError:
            missing.add(engine)
    return missing, errors
