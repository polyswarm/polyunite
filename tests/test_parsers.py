import json
import unittest

import polyunite
import pytest

from .conftest import open_fixture

def report_results():
    with open_fixture('report_results.json') as f:
        return json.load(f)

@pytest.mark.parametrize('expect', report_results(), ids='{engine}-{source}'.format_map)
def test_parsers(expect):
    vr = polyunite.parse(expect['engine'], expect['source'])
    assert vr.name == expect['name']
    assert vr.labels == set(expect['labels'])
