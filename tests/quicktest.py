import json
import pytest

import polyunite

from .utils import read_result_fixtures


def test_parsers():
    """
    Speedier tests, stops at first error.
    """
    for report_results in read_result_fixtures():
        engine = report_results['engine']
        source = report_results['source']
        actual = polyunite.parse(engine, source)
        if 'name' in report_results:
            expected_name = report_results['name']
            if expected_name != actual.name:
                pytest.fail(
                    f'[{engine}/{source}] name={actual.name} expected={expected_name}',
                    pytrace=False,
                )
        if 'labels' in report_results:
            expected_labels = set(report_results['labels'])
            if expected_labels != actual.labels:
                pytest.fail(
                    f'[{engine}/{source}] labels={actual.labels}, expected={expected_labels}',
                    pytrace=False,
                )
