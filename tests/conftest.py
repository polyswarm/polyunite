#!/usr/bin/env python3

import pytest
from contextlib import contextmanager
import csv
import json
import zipfile

import pkg_resources

import polyunite


@contextmanager
def open_fixture(filename, fname=None):
    zippath = 'fixtures/{}.zip'.format(fname or next(iter(filename.rsplit('.', 1))))
    with zipfile.ZipFile(pkg_resources.resource_filename(__name__, zippath)) as zf:
        with zf.open(filename) as f:
            yield f


def seen():
    with open_fixture('engine_families.csv') as f:
        yield from csv.reader(map(bytes.decode, f.readlines()))


def format_match(engine: 'str', label: 'str', vr: 'VocabRegex'):
    return ' | '.join((
        '{:<10}',
        '{:1}',
        '{:<10.10}',
        '{:<9.9}',
        '{:<10.10}',
        '{:30}',
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


def match_iter():
    missing = set()
    errors = []
    it = seen()
    for engine, label in seen():
        try:
            yield (engine, label, polyunite.parse(engine, label))
        except polyunite.errors.MatchError as e:
            errors.append((engine, label, e))
        except polyunite.errors.RegistryKeyError:
            missing.add(engine)
    return missing, errors
