import json
import pytest

import polyunite

from .conftest import open_fixture


@pytest.mark.parametrize(
    'engine,source,name,labels', [
        pytest.param(
            d['engine'],
            d['source'],
            d['name'],
            d.get('labels', []),
            id='{engine}/{source}'.format_map(d),
        ) for d in json.loads(open_fixture('report_results.json'))
    ]
)
def test_parsers(engine, source, name, labels):
    actual = polyunite.parse(engine, source)
    assert name == actual.name
    assert set(labels) == actual.labels
