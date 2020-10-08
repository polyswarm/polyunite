import polyunite
import pytest


@pytest.mark.parametrize('expected, names', [
    ('Zeus', ('Zeus', 'Zlob', 'zlob', 'zbot', 'zeus', 'Zeus-Trojan')),
    ('Zlob', ('Zeus', 'Zlob', 'zlob', 'zbot', '', None)),
])
def test_guess_malware_name(expected, names):
    assert expected == polyunite.guess_name(names)
