import json
import pytest
import unittest

import polyunite

from .conftest import open_fixture


def report_results():
    with open_fixture('report_results.json') as f:
        return [{
            'engine': e['engine'],
            'source': e['source'],
            'name': e['name'],
            'labels': set(e['labels']),
        } for e in json.load(f)]


@pytest.mark.parametrize('expected', report_results(), ids='{engine}/{source}'.format_map)
def test_parsers(expected):
    vr = polyunite.parse(expected.pop('engine'), expected.pop('source'))
    assert expected == {k: getattr(vr, k) for k in expected.keys()}
