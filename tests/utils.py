#!/usr/bin/env python3

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


def generate_fixtures():
    fxes = []
    for engine, label, vr in match_iter():
        fxes.append({
            'engine': str(vr.__class__.__name__),
            'source': label,
            'name': vr.name,
            'labels': list(vr.labels),
            'operating_system': vr.operating_system,
            'macro': vr.macro,
            'language': vr.language,
            'is_heuristic': vr.is_heuristic,
        })
    return fxes


def engine_regexes():
    for engine, obj in polyunite.registry.items():
        yield (engine, obj.pattern)


def colorized_report():
    def print_heading(msg):
        print("{:-^150}".format(msg))

    try:
        it = match_iter()
        while True:
            print(format_match(*next(it)))
    except StopIteration as e:
        missing, errors = e.value

    print_heading("FAILURES")
    for engine, label, err in errors:
        print("{:<15}: {:85} : {}".format(engine, label, err))

    print_heading("INFO")
    print('compile.cache_info: ', polyunite.vocab.VocabRegex.compile.cache_info())

    print_heading("MISSING")
    print(missing)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--colorize', help='Print colorized report', action='store_true')
    parser.add_argument('-x', '--regexes', help='Print each engines regexes', action='store_true')
    parser.add_argument(
        '--build-fixtures',
        help='Dump the current report results, suitable for building fixtures',
        action='store_true'
    )
    args = parser.parse_args()
    if args.colorize:
        colorized_report()
    elif args.regexes:
        for engine, regex in engine_regexes():
            print('Engine: {}\nRegex: {}'.format(engine, regex))
    elif args.build_fixtures:
        import json
        print(json.dumps(generate_fixtures(), indent=2))
