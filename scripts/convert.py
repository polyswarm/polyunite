import sys
import regex as re
from pathlib import Path
from collections import Counter

try:
    from utils import read_family_fixtures
except:
    sys.path.append(str(Path(__file__).parent.joinpath('../tests')))
    from utils import read_family_fixtures

from polyunite.vocab import TYPES, SUFFIXES, BEHAVIORS, OSES, ARCHIVES, MACROS, LANGS, HEURISTICS, LABELS

from polyunite.vocab._base import VocabRegex
from polyunite.utils import group
"""
# The 70 thing

Win32/Sorter.AutoVirus.70Worm.A
Win32/Sorter.AutoVirus.70YPInstallerCRC.A
Win32/Sorter.AutoVirus.ExeKiller.A
Win32/Sorter.AutoVirus.70DLGInstall.B


# Other
Trojan.Clicker-DOTHETUK!8.E825

"""

ACCOUNT_TYPE = VocabRegex.from_resource('ACCOUNT_TYPE')
_LXL = group(
    'Net', 'Sorter.Autovirus', 'Sorter.AVE', 'Notifier', 'IRC-Worm', 'Behav', 'Expiro', 'Intended',
    'WOX', 'Mailfinder', LABELS, OSES, ARCHIVES, MACROS, LANGS, HEURISTICS,
    BEHAVIORS, ACCOUNT_TYPE
)
_FAMILY = group(
    '((CVE|Cve|cve|CAN)([-_]?([0-9]{4})([-_]?(([0-9]+)[[:alpha:]]*))?)?)',
    '((?i:MS)([0-9]{2})-?([0-9]{1,3}))',
    r'\w+',
    '[A-Z]{1,3}-[A-Z]*(?:[A-Z][a-z]+)+',
    '[A-Z][[:alnum:]]*-[[:alnum:]]+',
    'km_[a-f0-9]+',
    # Win32/Sorter.AutoVirus.70YPInstallerCRC.A
    '70[A-Za-z]+',
    _LXL,
)


def convert(s, label=_LXL, family=_FAMILY):
    variants = (
        r'[.]origin',
        r'[.]None',
        # Win32/Trojan.Klone.HyEAqRMA	Win64/Adware.Generic.HgEASOMA
        r'[.]H[[:alnum:]]{4,8}',
        # Android.Hiddenapp.A1f0e	Android.Knobot.A3fe7
        r'[.]A[a-f0-9]{4}',
        # Trojan.Spy.GhostSpy.50.b	 Trojan.MoonPie.11.a
        r'[.][0-9]{1,3}[.][a-z]',
        # Backdoor/Huigezi.2007.auqh
        r'[.]20[0-9][0-9][.][a-z]+',
        # TrojanDownloader.Geral.i8
        r'[.][a-z][0-9]{1,3}',
        # Adware.Dealply.P10
        r'[.][A-Z0-9]{1,3}',
        # Trojan.Emotet.MUE.A5
        r'[.]MUE[.][A-Z0-9]{1,3}',
        # Trojan:Win32/Patcher.d8
        r'[.][a-f0-9]{2}$',
        # Worm/W32.SillyP2P.Zen.B,
        r'[.]Zen[.][A-Z]',
        # Trojan/W32.VB-VBKrypt.1576960.B	Trojan/W32.Agent.212992.XPB	Backdoor/W32.Padodor.6145.I
        r'[.][0-9]{4,6}[.][A-Z]{1,4}',
        # Trojan/W32.VB-Agent.53289	Trojan-Clicker/W32.DP-AdBar.1202176
        r'[.][0-9]{4,7}',
        # Backdoor:Win32/IRCBot.1f4
        r'[.][a-f0-9]{3}',
        # Trojan-Downloader.Win32.Delf.CQ
        r'[.][A-Z]{1,3}',
        # Backdoor/SdBot.axp
        r'[.][a-z]{1,3}$',
        # Worm.Strictor.S5	PUA.LLCMail.DC7 	TrojanRansom.Crowti.A4	PUA.HacKMS.A5
        r'[.][A-Z]{1,2}[0-9]',
        # PUA.MediadrugPMF.S5661312	Trojan.TinbaCS.S11802369	Trojan.ZusyCS.S21035
        r'[.]S[0-9]{4,12}',
        # Trojan/W32.DP-Viking.25088.B
        r'[.][0-9]{5}.[A-Z]',
        # Backdoor/W32.DP-BlackHole.491008
        r'[.][0-9]{6}',
        # Win.Trojan.Agent-358135
        r'[-][0-9]{5,8}',
        # Virus/W32.Ramnit.C
        r'[.][A-Z]',
        # Trojan.Win32.LdPinch.fmye	Trojan.Win32.Small.cvsagm
        r'[.][a-z]{4,7}',
        # Trojan.Tenagour.3,
        r'[.][0-9]{1,4}',
        # PUA.Win.Packer.Purebasic-2
        r'-[0-9]{1,4}',
        # Trojan:Win32/starter.ali1000139
        r'[.]ali[0-9]{6,}',
        # Trojan.Click.9832
        r'[.][0-9]{2,}',
        # Trojan.8D1F209143C1068C
        r'[.][A-F0-9]{16}',
        # Suspicious:Suspicious.C9C2@17558BEC.mg
        r'[.][A-F0-9/#@.]{12,}[.]mg',
        # Trojan.Bifrose!3F3F
        r'![A-F0-9]{1,4}',
        # Trojan.AndroidOS.Geinimi.C!c
        r'[.][A-Za-z][!][A-Za-z0-9]',
        # Trojan.Win32.Ressdt.5!c
        r'[.][0-9][!][a-z]',
        # Malware.Generic.6!tfe
        r'[.][0-9][!]tfe',
        # Win.Trojan.Agent-90809-1, Win.Malware.Farfli-6824120-0
        r'[-][0-9]{5,7}[-][0-9]',
        # Win.Adware.Agent-1138899
        r'[-][0-9]{7}',
        # Trojan:Win32/Generic.ec120d93
        r'[.][a-f0-9]{8}',
        # Malware.Heuristic!ET#100%
        r'!ET(#(100|[1-9][0-9]?)%)?',
        # AdWare.Win32.HotBar.da#RSUNPACK.a, Backdoor.Win32.RemoteABC.exb#RSUNPACK.a
        r'[.][a-z]{2,3}#RSUNPACK[.][a-z]',
        # Trojan-Spy.Prepscram.dam#2
        r'[.](dam)#[0-9]',
        # Malware.ObfusVBA@ML.87
        r'[@][A-Z]{2}[.][0-9]{1,3}',
        # Worm.Nimda!8.F, Trojan.Clicker-Agent!8.13, Downloader.Delf!8.16F, Ransom.Wannacrypt!8.E720
        # Malware.FakePDF/ICON!1.A24C
        # Exploit.CVE-2017-11882/SLT!1.AEE3
        # Downloader.StealthLoader/APT#TA505!1.BD87
        # Malware.FakePIC@CV!1.6AB7	Trojan.Bayrob@VE!1.A37E	Virus.VirLock@EP!1.A247
        # Virus.Parite#dll!1.A144
        r'([/][A-Z]+)?([#][[:alnum:]]+)?(@[A-Z]+)?[!][0-9][.][A-F0-9]{1,5}',
        # Trojan.Fuerboos!8.EFC8/N3#91%
        r'![0-9][.][0-9A-F]{4}/([A-Z][A-Z0-9])#(100|[1-9][0-9]?)%',
        # Backdoor.Boychi[HT]!1.A08F
        r'\[[A-Z]{2}\][!][0-9][.][A-F0-9]{4}',
        # Exploit.CVE-2012-0158(X)!1.A584
        r'\([A-Z][a-z]*\)[!][0-9][.][A-F0-9]{4}',
        # Win.Malware.Agent1070901705/CRDF-1
        r'/CRDF-[0-9]',
        # Win.Trojan.Generic-2-6449654-0
        r'-[0-9]-[0-9]{7}-[0-9]',
        # Js.Trojan.Agent-1553495-4663817-1
        r'-[0-9]{7}-[0-9]{7}-[0-9]',
        # Win.Spyware.26904-1, Win.Downloader.103202-1
        r'[.][0-9]{5,6}-[0-9]',
        # Worm.ChineseHacker-2.a
        r'-[0-9][.][a-z]',
        # Trojan ( 0052c6631 )
        # r'\s*\(\s*[a-f0-9]{8,12}\s*\)\s*',
        # Trojan.CYWATCH-A-000067
        r'-[A-Z]-[0-9]{6}',
        # Virus.MSWord.Twno.D:Tw
        r'[.][A-Z]:[A-Z][a-z]',
        # Win.Virus.Sality:1-6335700-1
        r':[0-9]-[0-9]{6,8}-[0-9]',
        # Trojan-Heur/Win32.TP.FK6@benBK0db
        r'[.][A-Z0-9]{2}[.][A-Z0-9]@[A-Za-z0-9]{8}',
    )

    prefixes = [
        r'not-a-virus:', r'not-a-Vius', r'[Hh]eur:', r'HEUR:', r'UDS:', r'[Gg]en:', r'modification\sof\s',
        r'possibly\s', r'probably\s', r'possible-Threat.', 'BehavesLike', 'Suspicious:'
    ]

    namesuffix = [
        '[.-]based',
    ]

    s = re.escape(s)
    s = s.replace('<Label>', label).replace('<Family>', family).replace('<Kind>', family)
    vg = '|'.join(variants)
    pz = '|'.join(prefixes)
    nz = '|'.join(namesuffix)
    pat = re.compile(rf'^({pz})*{s}({nz})?({SUFFIXES:-g})?({vg})?({SUFFIXES:-g})?$')
    return pat


patterns = [
    # convert(ss, family=r'(km_[a-f0-9]+|[0-9a-z]*[A-Z][a-zA-Z0-9._-]+|[a-z]{4,})') for ss in [
    convert(ss) for ss in [
        '<Family>',
        '<Label>.<Family>',
        # Backdoor/Nucledor.11.c
        '<Label>/<Family>',
        '<Label>.<Label>.<Family>',
        '<Label>.<Label>.<Label>.<Family>',
        '<Label>/<Label>.<Family>',
        # Backdoor.Dropper/Mirai!1.BC48
        '<Label>.<Label>/<Family>',
        # Backdoor.Mirai/Linux!1.BC48
        '<Label>.<Family>/<Label>',
        'Suspicious:<Family>',
        # possible-Threat.Joke.SuspectCRC
        'possible-Threat.<Label>.<Family>',
        # Trojan:Win32/Fareit.2ed
        '<Label>:<Label>/<Family>',
        '<Label>-<Label>.<Family>',
        # Trojan-PWS/W32.OnLineGames
        '<Label>-<Label>/<Label>.<Family>',
        # Backdoor.[OceanLotus]Salgorea!1.C3DC
        '<Label>.[<Family>]<Family>',
        '<Label>:<Family>',
        '<Label>[<Label>]/<Label>.<Family>',
        # Trojan[Proxy]/Win32.Coledor
        # '<Label><Label>:<Label>/<Family>',
        # Trojan-Dropper.Win32.Multibinder
        '<Label>-<Label>.<Label>.<Family>',
    ]
] + [
    # re.compile(rf'^{_LXL}({_LXL})?:{_LXL}/.+.[a-f0-9]{{8}}$'),
    re.compile(r'^[A-Z][a-z]+(?:\s[[:alpha:]]+)+$'),
]

excluded = [
    re.compile(r'^[\w-]+ \( [0-9A-Fa-f]+ \)'),
    re.compile(r'.*QVM[0-9]+.*'),
    re.compile('EICAR Anti-Virus Test File'),
    re.compile('EICAR File'),
    re.compile('Error! An Error occurred when scanning a file'),
    re.compile('EICAR Test File'),
]

counter = Counter()

for engine, _, line in read_family_fixtures():
    if any(p.match(line) for p in excluded):
        counter['skipped'] += 1
    elif any(p.fullmatch(line) for p in patterns):
        counter['successful'] += 1
    else:
        counter['unsuccessful'] += 1
        print(line)

print(counter)
