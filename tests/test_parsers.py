import json
import pytest

import polyunite

from .conftest import open_fixture


@pytest.mark.parametrize(
    'report_results',
    json.loads(open_fixture('report_results.json')),
    ids='{engine}/{source}'.format_map,
)
def test_parsers(report_results):
    actual = polyunite.parse(report_results['engine'], report_results['source'])

    if 'name' in report_results:
        assert report_results['name'] == actual.name

    if 'labels' in report_results:
        assert set(report_results['labels']) == set(actual.labels)
