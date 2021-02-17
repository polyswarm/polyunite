from contextlib import contextmanager
import csv
from io import TextIOWrapper
import json
import os.path
from zipfile import ZipFile

import polyunite


@contextmanager
def open_fixture(filename, rootdir=os.path.join(os.path.dirname(__file__), 'fixtures')):
    name, _ = os.path.splitext(filename)

    with ZipFile(os.path.join(rootdir, name + '.zip'), mode='r') as zf:
        with zf.open(filename, mode='r') as f:
            yield TextIOWrapper(f, encoding='utf8')


def read_result_fixtures():
    with open_fixture('report_results.json') as f:
        return json.load(f)


def read_family_fixtures(only=None):
    with open_fixture('engine_families.csv') as fixtures:
        rows = csv.reader(fixtures)

        # Skip header
        hdr = next(rows)
        if hdr != ['engine', 'instance_id', 'classification']:
            raise ValueError("Invalid CSV Header: %s" % hdr)

        if only:
            rows = filter(lambda row: row[0] in only, rows)

        yield from rows


def match_iter(only=None):
    missing = set()
    errors = []

    for engine, _, label in read_family_fixtures(only=only):
        try:
            yield polyunite.parse(engine, label)
        except polyunite.errors.MatchError as e:
            errors.append((engine, label, e))
        except polyunite.errors.RegistryKeyError:
            missing.add(engine)

    return missing, errors
