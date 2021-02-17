#!/usr/bin/env python3

import csv
import os.path
from zipimport import zipimporter

import polyunite


def open_fixture(filename):
    name, _ = filename.split('.')
    path = os.path.join(os.path.dirname(__file__), 'fixtures', f'{name}.zip')
    return zipimporter(path).get_data(filename)


def read_families():
    fixtures = open_fixture('engine_families.csv')
    for row in csv.DictReader(fixtures.decode('utf-8').splitlines()):
        yield row['engine'], row['instance_id'], row['classification']


def seen():
    for engine, _, classification in read_families():
        yield engine, classification


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
