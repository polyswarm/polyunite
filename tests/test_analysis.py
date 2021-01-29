import pytest

import polyunite

TEST_BOUNTIES = [
    (
        'SubSeven', {'trojan', 'backdoor'}, {
            'Alibaba': 'Win32/SubSeven.6ca32fd3',
            'ClamAV': 'Win.Trojan.SubSeven-38',
            'DrWeb': 'BackDoor.SubSeven.145',
            'Jiangmin': 'Backdoor/SubSeven.22.a',
            'Lionic': 'Trojan.Win32.SubSeven.m!c',
            'NanoAV': 'Trojan.Win32.SubSeven.dqcy',
        }
    ),
    (
        'Qukart', {'greyware', 'backdoor', 'trojan', 'virus', 'ransomware', 'worm'}, {
            'CrowdStrike Falcon': 'win/malicious',
            'DrWeb': 'BackDoor.HangUp.43882',
            'FilSecLab': 'Trojan.5137BDB1395FE83B',
            'Ikarus': 'Trojan.Win32.Senta',
            'Jiangmin': 'TrojanProxy.Qukart.dyoi',
            'K7': 'Proxy-Program ( 00557ea51 )',
            'NanoAV': 'Trojan.Win32.Qukart.fnzitw',
            'Qihoo 360': 'HEUR/QVM19.1.4BF9.Malware.Gen',
            'Quick Heal': 'Worm.Dorkbot.A',
            'Rising': 'Ransom.PornoAsset!8.6AA',
            'XVirus': 'Backdoor.Berbew.192'
        }
    ),
    (
        'ShipUp', {'trojan', 'dropper'}, {
            'Alibaba': 'TrojanDropper:Win32/ShipUp.a8d51701',
            'ClamAV': 'Win.Trojan.Redirect-6055402-0',
            'DrWeb': 'Trojan.Redirect.140',
            'Ikarus': 'Trojan.Win32.ShipUp',
            'Jiangmin': 'Trojan/ShipUp.iz',
            'K7': 'Trojan ( 0055e3dd1 )',
            'Lionic': 'Trojan.Win32.ShipUp.4!c',
            'NanoAV': 'Trojan.Win32.ShipUp.brneld',
            'Qihoo 360': 'Win32/Trojan.ebb',
            'Quick Heal': 'Trojan.Mauvaise.SL1',
            'Rising': 'Dropper.Gepys!8.15D'
        }
    ),
    (
        'Mepaow', {'trojan', 'virus', 'prepender'}, {
            'ClamAV': 'Win.Malware.Mepaow-6725393-0',
            'DrWeb': 'Win32.HLLP.Stone.2',
            'Ikarus': 'Trojan.Win32.Mepaow',
            'Lionic': 'Virus.Win32.Lamer.n!c',
            'NanoAV': 'Virus.Win32.Mepaow.btvwx',
            'Qihoo 360': 'Win32/Virus.947',
            'Quick Heal': 'Trojan.Agent',
            'Rising': 'Malware.Heuristic!ET#84%'
        }
    ),
    (
        'Upantix', {'trojan', 'security_assessment_tool'}, {
            'Alibaba': 'Trojan:Win32/Skeeyah.a427b927',
            'DrWeb': 'Trojan.Packed2.39727',
            'K7': 'Trojan ( 0050a9591 )',
            'Lionic': 'Hacktool.Win32.Upantix.x!c'
        }
    ),
    (
        'BtcMine', {'cryptominer', 'trojan'}, {
            'DrWeb': 'Trojan.BtcMine.3368',
            'Ikarus': 'Trojan.Win64.CoinMiner',
        }
    ),
]


@pytest.mark.parametrize('family,_labels,results', TEST_BOUNTIES)
def test_guess_malware_name(family, _labels, results):
    assert family == polyunite.infer_name(results)


@pytest.mark.parametrize('_family,labels,results', TEST_BOUNTIES)
def test_summarize_labels(_family, labels, results):
    assert labels == set(polyunite.summarize(results, key=lambda o: o.labels))


@pytest.mark.parametrize('_family,_labels,results', TEST_BOUNTIES)
def test_summarize_os(_family, _labels, results):
    assert 'Windows' == next(polyunite.summarize(results, lambda o: o.operating_system, top_k=1))
