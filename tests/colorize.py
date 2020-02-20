import csv
import os
import sys

import polyunite


def seen(f):
    with open(f, newline='') as csvfile:
        yield from csv.reader(csvfile)


if len(sys.argv) == 1:
    for name, family in seen(f'{os.path.dirname(__file__)}/fixtures/engine_families.csv'):
        if name in polyunite.Schemes:
            sch = polyunite.Schemes[name](family)
            try:
                print(
                    '{:<10} {:1} {:1} {:>9.9} {:>10.10} {:>12.12} {:85}'.format(
                        name,
                        'H' if sch.heuristic else ' ',
                        'T' if sch.malice_unlikely else ' ',
                        str(sch.operating_system or '    '),
                        str(sch.label),
                        str(sch.name),
                        sch.colorize(),
                    )
                )
            except TypeError as e:
                print("Couldn't parse '%s' as a %s name" % (family, name))
                print("Err: ", e)
    sys.exit(0)

elif len(sys.argv) == 2:
    if sys.argv[1] == '-r':
        # print regular expressions for each engine
        for name, engine in polyunite.Schemes.items():
            print("%s: \n%s\n" % (name, engine.rgx.pattern))
        sys.exit(0)

raise NotImplementedError
