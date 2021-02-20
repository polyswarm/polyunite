import pytest

import polyunite

from .utils import read_result_fixtures

@pytest.mark.parametrize(
    'engine,source,name,labels', [
        pytest.param(
            d['engine'],
            d['source'],
            d['name'],
            d.get('labels', []),
            id='{engine}/{source}'.format_map(d),
        ) for d in read_result_fixtures()
    ]
)
def test_parsers(engine, source, name, labels):
    actual = polyunite.parse(engine, source)
    assert name == actual.name
    assert set(labels) == actual.labels
