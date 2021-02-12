import json
import pytest

import polyunite

from .conftest import open_fixture



# def test_parsers():
#     """
#     Speedier tests, stops at first error.
#     """
#     for report_results in json.loads(open_fixture('report_results.json')):
#         engine = report_results['engine']
#         source = report_results['source']
#         actual = polyunite.parse(engine, source)
#         if 'name' in report_results:
#             expected_name = report_results['name']
#             if expected_name != actual.name:
#                 pytest.fail(
#                     f'[{engine}/{source}] name={actual.name} expected={expected_name}',
#                     pytrace=False,
#                 )
#         if 'labels' in report_results:
#             expected_labels = set(report_results['labels'])
#             if expected_labels != actual.labels:
#                 pytest.fail(
#                     f'[{engine}/{source}] labels={actual.labels}, expected={expected_labels}',
#                     pytrace=False,
#                 )


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
        assert set(report_results['labels']) == actual.labels
