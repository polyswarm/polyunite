import polyunite
from operator import attrgetter
import pytest

SUB7_BOUNTY = {
    'Alibaba': 'Win32/SubSeven.6ca32fd3',
    'ClamAV': 'Win.Trojan.SubSeven-38',
    'DrWeb': 'BackDoor.SubSeven.145',
    'Jiangmin': 'Backdoor/SubSeven.22.a',
    'Lionic': 'Trojan.Win32.SubSeven.m!c',
    'NanoAV': 'Trojan.Win32.SubSeven.dqcy',
}


@pytest.mark.parametrize('expected, results', [
    ('SubSeven', SUB7_BOUNTY),
])
def test_guess_malware_name(expected, results):
    assert expected == polyunite.infer_name(results)


@pytest.mark.parametrize('expected, results', [
    ({'backdoor', 'trojan'}, SUB7_BOUNTY),
])
def test_summarize_labels(expected, results):
    assert expected == set(polyunite.summarize(results, key=attrgetter('labels')))


@pytest.mark.parametrize('expected, results', [
    ('Windows', SUB7_BOUNTY),
])
def test_summarize_os(expected, results):
    os, *_ = polyunite.summarize(results, key=attrgetter('operating_system'), top_k=1)
    assert expected == os
