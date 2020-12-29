import pytest

import polyunite


@pytest.mark.parametrize(
    'is_heuristic, engine, family', [
        (True, 'Alibaba', 'Linux/Agent.981bab81'),
        (True, 'alibaba', 'Linux/Agent.981bab81'),
        (False, 'NOT A REAL ENGINE', 'Linux/Agent.981bab81'),
        (False, 'alibaba', None),
        (False, 'alibaba', 1923),
    ]
)
def test_is_heuristic(is_heuristic, engine, family):
    assert is_heuristic == polyunite.is_heuristic(engine, family)
