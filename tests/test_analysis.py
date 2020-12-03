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
