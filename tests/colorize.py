import csv
import os
import sys
import zipfile  # noqa

import pkg_resources  # noqa

try:
    import polyunite  # noqa
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import polyunite


def seen():
    with zipfile.ZipFile(pkg_resources.resource_filename(__name__, f'fixtures/engine_families.zip')) as zf:
        with zf.open('engine_families.csv') as csvfile:
            yield from csv.reader(map(bytes.decode, csvfile.readlines()))


if len(sys.argv) == 1:
    missing = set()
    errors = []
    for engine, family in seen():
        try:
            sch = polyunite.parse(engine, family)
            print(
                ' | '.join(
                    ('{:<10}', '{:1}', '{:<10.10}', '{:<9.9}', '{:<10.10}', '{:30}', '{:>15.15}', '{}')
                ).format(
                    engine,
                    sch.is_heuristic and 'H' or '',
                    sch.operating_system or '',
                    sch.language or '',
                    sch.macro or '',
                    ', '.join(sch.labels),
                    sch.name,
                    sch.colorize(),
                )
            )
        except polyunite.errors.MatchError as e:
            errors.append((engine, family, e))
        except polyunite.errors.EngineKeyError:
            missing.add(engine)
    print("{:-^150}".format("FAILURES"))
    for engine, family, err in errors:
        print("{:<15}: {:85} : {}".format(engine, family, err))
    print("{:-^150}".format("INFO"))
    print('compile.cache_info', polyunite.VocabRegex.compile.cache_info())
    print('Missing:', missing)

elif len(sys.argv) == 2 and sys.argv[1] == '-r':
    # print regular expressions for each engine
    for engine, obj in polyunite.engines.items():
        print("%s: \n%s\n" % (engine, obj.pattern.pattern))
