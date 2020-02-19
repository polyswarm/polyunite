import csv
import os

import polyunite
import sys


def seen(f):
    with open(f, newline='') as csvfile:
        yield from csv.reader(csvfile)


if len(sys.argv) == 1:
    for name, family in seen(f'{os.path.dirname(__file__)}/fixtures/engine_families.csv'):
        if name in polyunite.Schemes:
            print('%-10s' % name, polyunite.Schemes[name](family).colorize())
    sys.exit(0)

elif len(sys.argv) == 2:
    if sys.argv[1] == '-r':
        # print regular expressions for each engine
        for name, engine in polyunite.Schemes.items():
            print("%s: \n\n%s\n" % (name, engine.rgx))
        sys.exit(0)

raise NotImplementedError
