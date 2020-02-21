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
    for engine, family in seen():
        sch = polyunite.Schemes.parse(engine, family)
        if sch:
            try:
                print(
                    '{:<10} {:1} {:1} {:<15.12} {:30.30} {:>16.16} {}'.format(
                        engine,
                        'H' if sch.heuristic else ' ',
                        'T' if sch.malice_unlikely else ' ',
                        str(sch.operating_system or '    '),
                        str(', '.join(sch.label)),
                        str(sch.name),
                        sch.colorize(),
                    )
                )
            except TypeError as e:
                print("Couldn't parse '%s' as a %s name" % (family, engine))
                print("Err: ", e)
        else:
            missing.add(engine)
    print("No name scheme found for: ", missing)
    sys.exit(0)

elif len(sys.argv) == 2:
    if sys.argv[1] == '-r':
        # print regular expressions for each engine
        for engine, obj in polyunite.Schemes.items():
            print("%s: \n%s\n" % (engine, obj.rgx.pattern))
        sys.exit(0)

raise NotImplementedError
