import csv
import os
import sys
import zipfile

import pkg_resources

import polyunite


def seen():
    with zipfile.ZipFile(pkg_resources.resource_filename(__name__, f'fixtures/engine_families.zip')) as zf:
        with zf.open('engine_families.csv') as csvfile:
            yield from csv.reader(map(bytes.decode, csvfile.readlines()))


if len(sys.argv) == 1:
    missing = set()
    errors = []
    for engine, family in seen():
        sch = polyunite.Schemes.parse(engine, family)
        if sch:
            try:
                colorized = sch.colorize()
                if not colorized:
                    raise TypeError
                print(
                    '{:<10} {:1} {:1} {:<10.10} {:<8.8} {:<10.10} {:30.30} {:>16.16} {}'.format(
                        engine,
                        sch.heuristic and 'H' or ' ',
                        sch.peripheral and 'T' or ' ',
                        sch.operating_system or '    ',
                        sch.language or '    ',
                        sch.macro or '    ',
                        ', '.join(sch.labels),
                        sch.name,
                        colorized,
                    )
                )
            except TypeError as e:
                errors.append((engine, family, e))
        else:
            missing.add(engine)
    print("{:-^100}".format("FAILURES"))
    for engine, family, err in errors:
        print("{:<15}: {:85} : {}".format(engine, family, err))
    print("\nNo name scheme found for: ", missing)
    sys.exit(0)

elif len(sys.argv) == 2:
    if sys.argv[1] == '-r':
        # print regular expressions for each engine
        for engine, obj in polyunite.Schemes.items():
            print("%s: \n%s\n" % (engine, obj.rgx.pattern))
        sys.exit(0)

raise NotImplementedError
