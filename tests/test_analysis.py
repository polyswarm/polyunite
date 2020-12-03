import polyunite
import pytest


@pytest.mark.parametrize(
    'expected, results', [
        (
            'SubSeven', {
                'Alibaba': 'Win32/SubSeven.6ca32fd3',
                'ClamAV': 'Win.Trojan.SubSeven-38',
                'DrWeb': 'BackDoor.SubSeven.145',
                'Jiangmin': 'Backdoor/SubSeven.22.a',
                'Lionic': 'Trojan.Win32.SubSeven.m!c',
                'NanoAV': 'Trojan.Win32.SubSeven.dqcy',
            }
        ),
    ]
)
def test_guess_malware_name(expected, results):
    assert expected == polyunite.infer_name(results)


@pytest.mark.parametrize(
    'expected, results', [
        (
            {'backdoor', 'trojan'}, {
                'Alibaba': 'Win32/SubSeven.6ca32fd3',
                'ClamAV': 'Win.Trojan.SubSeven-38',
                'DrWeb': 'BackDoor.SubSeven.145',
                'Jiangmin': 'Backdoor/SubSeven.22.a',
                'Lionic': 'Trojan.Win32.SubSeven.m!c',
                'NanoAV': 'Trojan.Win32.SubSeven.dqcy',
            }
        ),
    ]
)
def test_gather_labels(expected, results):
    assert expected == set.union(*(c.labels for _, c in polyunite.each(results)))
