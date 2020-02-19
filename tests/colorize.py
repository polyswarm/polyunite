import csv
import os

import polyunite


def seen(f):
    with open(f, newline='') as csvfile:
        yield from csv.reader(csvfile)


for name, family in seen(f'{os.path.dirname(__file__)}/fixtures/engine_families.csv'):
    if name in polyunite.Schemes:
        res = polyunite.Schemes[name](family)
        print('%-10s' % name, res.colorize())
        # print("ENGINE: %s = %s" % (engine, NamingScheme._engines[NamingScheme.to_engine(engine)].rgx))
        # print(res)
