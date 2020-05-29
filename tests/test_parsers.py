import pytest
import json
import polyunite
from tests import utils

with utils.open_fixture('report_results.json') as f:
    results = json.load(f)

def report_results():
    for result in results:
        engine = result['engine']
        src = result['source']
        yield pytest.param(
            engine,
            src,
            result['name'],
            set(result['labels']),
            id=f'{engine}[{src}]',
        )


@pytest.mark.parametrize("engine, src, name, labels", report_results())
def test_parsers(engine, src, name, labels):
    vr = polyunite.parse(engine, src)
    assert vr.name == name
    assert vr.labels == labels
