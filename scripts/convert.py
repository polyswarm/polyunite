import sys
import regex as re
from itertools import product
import string
from pprint import pprint
from pathlib import Path
from collections import Counter, defaultdict

try:
    from utils import read_family_fixtures
except:
    sys.path.append(str(Path(__file__).parent.joinpath('../tests')))
    from utils import read_family_fixtures

from polyunite.vocab import TYPES, SUFFIXES, BEHAVIORS, OSES, ARCHIVES, MACROS, LANGS, HEURISTICS, LABELS, PROTOCOLS

from polyunite.vocab._base import VocabRegex
from polyunite.utils import group
"""
# The 70 thing

Win32/Sorter.AutoVirus.70Worm.A
Win32/Sorter.AutoVirus.70YPInstallerCRC.A
Win32/Sorter.AutoVirus.ExeKiller.A
Win32/Sorter.AutoVirus.70DLGInstall.B

# Only use "valid" VARIANTS

Don't add VARIANTS if they could interfere with a "family name" pattern

# Family-name expansion

    Heur.Krypt.f
    Heur.ARP.c

# Handle this

    PCK.Dumped
    Micro.Relax

## And this

    MULDROP.Trojan
    Sivis.Win32
    CIH.Win32

Do label matches first.

# Do "account types"

    PHISH.Yhoo

Win.Trojan.3270387-1
Win.Trojan.6995490-1

# Format

    |    Prefix    |         |Family|           |  Variant  |
    possible-Threat:Download.Virtumod-Heuristic.11ef904de9df0.Generic1
                    | Type |          | Affix |               |Suffix|

"""

ACCOUNT_TYPE = VocabRegex.from_resource('ACCOUNT_TYPE')
_LXL = group(
    LABELS,
    OSES,
    ARCHIVES,
    MACROS,
    LANGS,
    BEHAVIORS,
    ACCOUNT_TYPE,
    PROTOCOLS,
)

_LIT = group(
    LABELS.literals(),
    OSES.literals(),
    ARCHIVES.literals(),
    MACROS.literals(),
    LANGS.literals(),
    BEHAVIORS.literals(),
    ACCOUNT_TYPE.literals(),
    PROTOCOLS.literals(),
)

# Prefix
#   - Capitalized
#   - Number
#   - Lowercase
#   - [A-Z]{2,4}(?=[a-z])
# Rest letters
# Include length
#   - [a-z]
#   - [A-Z]
#   - [[:alpha:]]
#   - [[:alnum:]]
# Suffix
#   Using e.g (?<=[a-z])
#   - [0-9]+
#   - [A-Z]+
#   - [A-Z]
#   - [-_.][A-Z0-9]{1,4}
#   - [-_.]based

# Grouping
# [-_.]?

# _FAMILY = group(
#     r'((?:Exp|Exploit)[.])?((CVE|Cve|cve|CAN)([_.-]?([0-9]{4})([_.-]?(([0-9]+)[[:alpha:]]*))?)?)',
#     r'((?:Exp|Exploit)[.])?((?i:MS)([0-9]{2})-?([0-9]{1,3}))',
#     r'[A-Z][a-z]{2}',
#     # e.x `Hello_World99` & `Emotet`
#     r'([0-9]{1,3})?[A-Z]{4,8}([0-9]{1,3})?',
#     # Handle common year PREFIXES, like `2008Virus`
#     r'(?!.{1,3}($|[.!#@]))((?:20[012]\d|19[89]\d)(?=[A-Z]))?'
#     # Handle special PREFIXES, like `iPhone`, `X-Connect` or `eWorm`
#     r'(?:([a-z]{1,2}|[iIeExX]-)(?=[A-Z]))?'
#     # Handle up to 5 capitalized words, optionally separated by '-' or '_'
#     r'(?:'
#     r'(?:[A-Z]{1,5}|\d{1,2})[a-z]+'
#     r'(?:'
#         r'(?:[A-Z]{1,5}[a-z]+){1,4}'
#         r'|(?:_[A-Z]{1,5}[a-z]+){1,3}'
#         r'|(?:-[A-Z]{1,5}[a-z]+){1,3}'
#     r')?'
#     r'){i<=2:\d}'
#     # Handle upper-case suffixes like `FakeAV`
#     r'((?:[0-9]{1,3}|[A-Z]{1,3})(?![a-zA-Z0-9]))?((?<=[a-zA-Z0-9])_[a-z]+)?',
#     r'[A-Z][A-Z0-9]*[a-z]+'
#     r'[A-Z][a-z]+[A-Z0-9]*'
#     r'[iIeExX]-[A-Z][A-Z0-9]*[a-z]+'

#     # SMS_Attacker,
#     r'[A-Z]+_[A-Z][a-z]+',
#     # BlackstoneUSPL,
#     r'[A-Z][a-z]{3,}[A-Z]+',

#     # Serv-U
#     r'[A-Z][a-z]+-[A-Z0-9]',

#     # PDF-U3D
#     r'[A-Z][A-Z0-9][-_.][A-Z][A-Z0-9]',

#     # PEF13C	BO2K
#     r'[A-Z][A-Z0-9]{3,}',

#     # r'[[:alnum:]]+',
#     # r'[0-9]{1,4}[[:alpha:]]+',
#     # r'[A-Z]{1,3}-[A-Z]*(?:[A-Z][a-z]+)+',
#     # r'[A-Z][[:alnum:]]*-[[:alnum:]]+',
#     # r'[A-Z][[:alpha:]]+[_-]([A-Z][[:alpha:]]*|[A-Z0-9]+)',
#     # r'([A-Z][[:alpha:]]*|[A-Z0-9]+)[_-][A-Z][[:alpha:]]*',
#     # # Nukesped
#     # r'[A-Z]{1,6}[a-z]{2,}',
#     # # Inject1
#     # r'[A-Z][a-z]{2,}[0-9]',
#     # # Handle special PREFIXES, like `iPhone`, `X-Connect` or `eWorm`
#     # r'(?:(?:[a-z]{1,2}|[iIeExX]-))[A-Z][a-z]+',
#     # # Handle upper-case suffixes like `FakeAV`
#     # r'[A-Z]{1,6}[a-z]+((?:[0-9]{1,3}|[A-Z]{1,3})',
#     # # FunnyDreamTcpTransfer
#     # r'(?:[A-Z][a-z]+)+,'
#     # # BO2K-plugin-Stcpio
#     # r'[A-Z][[:alnum:]]+-[a-z]+-[A-Z][[:alnum:]]+',
#     # # BO2K.plugin.Stcpio
#     # r'[A-Z][[:alnum:]]+\.[a-z]+\.[A-Z][[:alnum:]]+',
#     # # PE-Exe
#     # r'[A-Z]+-[A-Z][a-z0-9]+',
#     # # C99Shell
#     # r'[A-Z][0-9]{1,5}[A-Za-z][a-z0-9]+',

#     # TrojanDownloader:Office/Specikr_macro.7e54b364
#     r'[A-Z][a-z]{2,}_[a-z]{2,}',
#     # TrojanDropper:Win32/ExeBundle_2x.95aedcbc
#     r'[A-Z][a-z]+[A-Z][a-z]+_[0-9a-z]{1,5}',
#     # Trojan:Package/phishing.2
#     r'[A-Z][_-][A-Z0-9][[:alpha:]]+',
#     # Trojan.Win32.BO-plugin-RCR.gtgj
#     r'[A-Z][[:alnum:]]+-[a-z]+-[A-Z][[:alnum:]]+',
#     # Marker.Win32.PE-Exe.bxzo
#     r'[A-Z][[:alpha:]]*[-_][A-Z][[:alpha:]]',
#     r'km_[a-f0-9]+',
#     # Win32/Sorter.AutoVirus.70YPInstallerCRC.A
#     r'70[A-Z]\w+',
#     _LXL,
# )

_FAMILY = group(
    r'((CVE|Cve|cve|CAN)([_.-]?([0-9]{4})([_.-]?(([0-9]+)[[:alpha:]]*))?)?)',
    r'((?i:MS)([0-9]{2})-?([0-9]{1,3}))',
    r'\w+',
    # Serv-U
    r"[A-Z][a-z]-[A-Z]",
    # VB-Agent
    r"[A-Z]+-[A-Z][[:alnum:]]+",
    # SMS_Attacker
    r"[A-Z]+_[A-Z][[:alnum:]]+",
    # Specikr_macro
    r"[A-Z][[:alpha:]]+_[a-z]+",
    # ExeBundle_2x
    r"[A-Z][[:alpha:]]+_[0-9][[:alpha:]]",
    # BO-plugin-RCR
    r"[A-Z][[:alnum:]]+-[a-z]+-[A-Z][[:alnum:]]+",
    # Trojan.Clicker-DOTHETUK!8.E825	Trojan.Flooder-VB!8.2F70	Trojan.DoS-DKToyBox!8.533A
    r"[A-Z][[:alpha:]]+-[A-Z][[:alpha:]]+",
)

# _FAMILY = group(
#     r'((?:Exp|Exploit)[.])?((CVE|Cve|cve|CAN)([_.-]?([0-9]{4})([_.-]?(([0-9]+)[[:alpha:]]*))?)?)',
#     r'((?:Exp|Exploit)[.])?((?i:MS)([0-9]{2})-?([0-9]{1,3}))',
#     # r'([a-z]+|[0-9]+)?[A-Z][A-Za-z0-9]+',
#     ## BASIC
#     # r'(?:[A-Z][a-z]{4,}){i<=4:[A-Z0-9]}',
#     # Basic
#     r"\d*[a-z]?[A-Z][[:alnum:]]+[a-z][[:alnum:]]*",
#     # njRAT
#     r"[a-z]+[A-Z]+",
#     # 4shared
#     r"[0-9][a-z]{4,}",
#     # Serv-U
#     r"[A-Z][a-z]-[A-Z]",
#     # VB-Agent
#     r"[A-Z]+-[A-Z][[:alnum:]]+",
#     # SMS_Attacker
#     r"[A-Z]+_[A-Z][[:alnum:]]+",
#     # Specikr_macro
#     r"[A-Z][[:alpha:]]+_[a-z]+",
#     # ExeBundle_2x
#     r"[A-Z][[:alpha:]]+_[0-9][[:alpha:]]",
#     # BO-plugin-RCR
#     r"[A-Z][[:alnum:]]+-[a-z]+-[A-Z][[:alnum:]]+",
#     r"[A-Z]+",
#     r"[A-Z]+[a-z]+_[0-9]+",
#     r"[A-Z][a-z][A-Z]?",
#     r"[A-Z][[:alnum:]]+-[A-Z][[:alnum:]]*",
#     _LIT,

#     # r'[[:alnum:]]*[A-Z][[:alnum:]]*[a-z][[:alnum:]]*',
#     # r'[a-z]?(?:[A-Z]+[a-z]+)+[0-9]+',
#     # # iBryte
#     # r'[a-z][A-Z][a-z]{3,}',
#     # r'[a-z]?[A-Z](?:[[:alpha:]]{2,}){i<=3:[-_]}[[:alpha:]]',
#     # r'[a-z]?(?:[A-Z](?:[a-z]{3,}){i<=3:[-_]}[a-z]){i<=6:[0-9]}',
#     # r'(?:[A-Z][a-z]{4,}){s<=4:[A-Z0-9]}',
#     # r'(?:[iIeExXu]-?)?[A-Z](?:[a-z]{4,}){s<=4:[A-Z_-]}[A-Za-z]',
#     # r'[A-Z]{1,2}[A-Za-z]+',
#     # r'[A-Z]{2,3}-[A-Z][A-Za-z]{2,}',
#     # r'(?i:BO2K|JS|Lnk|Ag|njRAT|ICQ|IRC|VB|HTML|WOW|Wow|Fgt|Udr|BHO|Bho|WoW|LMir)',
#     # # mIRC	njRAT
#     # r'[a-z]{1,2}(?:[A-Z]{3,})',
#     # # r'[A-Z](?:[a-z]{4,}){s<=2,i<=4:[-A-Z0-9]}[a-zA-Z]',
#     # # # # VB	CXX
#     # # # r'[A-Z]{2,3}',

#     # # # # SMS_Attacker,
#     # # # r'[A-Z]+_[A-Z][a-z]+',

#     # # # # BlackstoneUSPL,
#     # # # r'[A-Z][a-z]{3,}[A-Z]+',

#     # # # Serv-U
#     # # r'[A-Z][a-z]+-[A-Z0-9]',

#     # # # PDF-U3D
#     # # r'[A-Z][A-Z0-9][-_.][A-Z][A-Z0-9]',

#     # # # # PEF13C	BO2K
#     # # # r'[A-Z][A-Z0-9]{3,}',

#     # # ## MEDIUM
#     # # r'[0-9]{1,2}[a-z]{4,}',
#     # # r'[A-Z](?:[a-z]{3,}){i<=4:[A-Z0-9-_]}[a-z]',
#     # # r'[A-Z](?:[a-z]{4,}){s<=3:[A-Z0-9]}'

#     # # # # # njRAT
#     # # r'[a-z0-9]{2,}(?:[A-Z]{3,}){i<=4:[0-9]}',
#     # # r'(?:([A-Z]{1,3}|[A-Z][a-z]+)[-_][A-Z][a-z]+){i<=2:[0-9]}',
#     # # r'(?:[A-Z][a-z]+[-_][A-Z]+){i<=2:[0-9]}',
#     # # r'[a-z][A-Z]+[a-z]{2,}',
#     # # r'(?:[A-Z]{3,}-[A-Z]{3,}){d<=2:[A-Z]}',
#     # # r'(?:DoS|DDos)-[A-Z][[:alnum:]]+',

#     # # ## MEDIUM HIGH
#     # # r'[A-Z]{2,}[a-z]{2,}',
#     # # r'[A-Z](?:[a-z]{2,}){}'
#     # # r'[A-Z][a-z][A-Z]',
#     # # r'[A-Z][a-z]',
#     # # r'[A-Z][a-z]{2,3}',

#     # # ## High
#     # # r'[a-z](?:[a-z]+){i<=5:[A-Z0-9]}',
#     # # r'[A-Z]{4}[0-9]{4}',
#     # # r'[A-Z]+',

#     # # # # 4shared
#     # # # r'[0-9][A-Za-z][a-z]{2,}',

#     # # # # T57iq0ngh
#     # # # r'[A-Z][A-Z0-9]+[a-z0-9]{3,}',

#     # # # VB-Agent
#     # # r'[A-Z]{2}-[A-Z]+[a-z]{3,}',

#     # # # # SillyP2p, SillyP2P, Silly_P2P, Silly.P2P
#     # # # r'[A-Z][a-z][._]?[A-Z0-9]{2,4}',
#     # # r'([a-z]{1,2}|[iIeExXu]-?|[A-Z]?[0-9]{1,5})?[A-Z]+[a-z]+([_-]?([A-Z]+[a-z]+|[0-9]{1,5}[a-z]+)){,3}(?:[0-9]{1,6}|[A-Z]{1,6})?',

#     # # # TrojanDownloader:Office/Specikr_macro.7e54b364
#     # # r'[A-Z][a-z]{2,}_[a-z]{2,}',
#     # # # TrojanDropper:Win32/ExeBundle_2x.95aedcbc
#     # # r'[A-Z][a-z]+[A-Z][a-z]+_[0-9a-z]{1,5}',
#     # # # Trojan:Package/phishing.2
#     # # r'[A-Z][_-][A-Z0-9][[:alpha:]]+',
#     # # # Trojan.Win32.BO-plugin-RCR.gtgj
#     # # r'[A-Z][[:alnum:]]+-[a-z]+-[A-Z][[:alnum:]]+',
#     # # # Marker.Win32.PE-Exe.bxzo
#     # # r'[A-Z][[:alpha:]]*[-_][A-Z][[:alpha:]]',
#     # # r'km_[a-f0-9]+',
#     # # # Win32/Sorter.AutoVirus.70YPInstallerCRC.A	Intended/10past3.775
#     # # r'[1-9][0-9][A-Z]*[a-z]+(?:[0-9]+|[A-Z]+)?',
#     # # r'[a-z]+(?=[.][[:xdigit:]]{8}$)',
#     # # r'[a-z]+(?=[.][0-9]{1,2}$)',
#     # # r'[a-z]+(?=[.]ali[0-9]+$)',
#     # # r'[[:alnum:]]+[.-]based',
#     # # r'^[a-z]+$',
#     # # r'(?i:Silly.?P2P)',
#     # # r'[A-Z]{2}-[A-Z][[:alnum:]]+',
#     # _LXL,
#     # rf'(?>{_LXL}[.][A-Z][a-z]+|[A-Z][a-z]+[.][A-Z][a-z]+(?=[.-/])){{i<=4:[A-Z0-9]}}',
#     # rf'{_LXL}[.]({_LXL}|(?:[0-9]{1,4}|[a-z]{1,2}|[a-z]-)?[A-Z](?:[a-z]+){{i<=4:[A-Z0-9]}})',
# )

VARIANTS = [
    # Trojan:Win32/Patcher.D8
    r"[.][A-F][0-9]",
    # Trojan:Win32/Patcher.d8
    r"[.][a-f][0-9]",
    # GreenCaterpillar.1575f
    r"[.][a-f0-9]{4,7}",
    r"[.][[:xdigit:]]{1,2}",
    # Virus.Emotet.A	Virus/W32.Ramnit.C	Trojan-Downloader.Win32.Delf.CQ	Trojan.Peed.JEZ
    # Trojan.Generic19.CAKN
    r"[.][A-Z]{1,5}",
    # Virus.MSExcel.Laroux.Cs
    r"[.][A-Z][a-z]",
    # Backdoor/SdBot.axp
    r"[.][a-z]{1,6}",
    # Backdoor/Y3KRat.pro.01
    r"[.][a-z]{1,3}[.][0-9]{1,2}",
    # Trojan.Tenagour.3	Trojan.Emotet.323	Trojan.Click.9832	Trojan/W32.VB-Agent.53289	Trojan-Clicker/W32.DP-AdBar.1202176
    r"[.][1-9][0-9]{1,4}",
    # Adware.VBKrypt.P7	Adware.Dealply.P10	Ransom.GandCrab.MUE.YY5
    r"[.][A-Z]{1,2}[0-9]{1,2}",
    # TrojanDownloader.Geral.i8	Trojan.OnLineGames.xi5
    r"[.][a-z]{1,2}[0-9]{1,2}",
    # Trojan/PSW.EBTReporter.2x.b
    r"[.][0-9][a-z][.][a-z]",
    # Win32/Trojan.Klone.HyEAqRMA	Win64/Adware.Generic.HgEASOMA
    r"[.]H[a-z][[:alnum:]]{4,8}",
    # Android.Hiddenapp.A1f0e	Android.Knobot.A3fe7
    r"[.]A[a-f0-9]{2,5}",
    # Downloader.Dalexis.f.444
    r"[.][a-z][.][1-9][0-9]{2}",
    # Trojan.Spy.GhostSpy.50.b	 Trojan.MoonPie.11.a	Win95/Nathan.3520.a
    # Backdoor.Agobot.3.um	Backdoor.ProRat.19.gg
    r"[.][0-9]{1,3}[.][a-z]{1,2}",
    # Backdoor/Huigezi.2007.auqh
    r"[.]20[0-9][0-9][.][a-z]+",
    # Trojan/W32.VB-VBKrypt.1576960.B	Trojan/W32.Agent.212992.XPB	Backdoor/W32.Padodor.6145.I
    # Trojan/W32.VB-HackTool.196608.B	Trojan/W32.VB-VBKrypt.1576960.B
    r"[.][0-9]{4,6}[.][A-Z]{1,4}",
    # Backdoor:Win32/IRCBot.1f4
    r"[.][a-f0-9]{3,5}",
    # Worm.Strictor.S5	PUA.LLCMail.DC7 	TrojanRansom.Crowti.A4	PUA.HacKMS.A5
    r"[.][A-Z]{1,2}[0-9]",
    # PUA.MediadrugPMF.S5661312	Trojan.TinbaCS.S11802369	Trojan.ZusyCS.S21035
    r"[.]S[0-9]{4,12}",
    # Trojan/W32.VB-KillWin.16384
    r"[.][0-9]{5}",
    # Trojan.Win32.192512.fiauwl
    r"[.][1-9][0-9]{5}[.][a-z]{6}",
    # Trojan.Win32.cvqzzy.eanvxu
    r"[.][a-z]{6}[.][a-z]{6}",
    # Trojan.Win32.LdPinch.fmye	Trojan.Win32.Small.cvsagm
    r"[.][a-z]{4,6}",
    # Trojan.Bifrose!3F3F
    r"[!][A-F0-9]{1,4}",
    # Trojan.AndroidOS.Geinimi.C!c	Trojan.Win32.Delf.a!c	Trojan.Win32.Ressdt.5!c
    r"[.][A-Za-z0-9][!]c",
    # Trojan.Win32.Generic.13AC019D	Trojan:Win32/Generic.ec120d93
    r"[.](?:[a-f0-9]{8}|[A-F0-9]{8})",
    # Malware.Heuristic!ET#100%
    r"!ET(\#(100|[1-9][0-9]?)%)?",
    # Trojan-Spy.Prepscram.dam#2
    r"[.][a-z]{2,3}#[0-9]+",
    # AdWare.Win32.HotBar.da#RSUNPACK.a, Backdoor.Win32.RemoteABC.exb#RSUNPACK.a
    r"[.][a-z]{2,3}#[A-Z]+[.][a-z]",
    # Malware.ObfusVBA@ML.87
    r"[@][A-Z]{2}[.][1-9][0-9]{1,3}",
    # Trojan.Win32.et3.dwjnpz	Trojan.Win32.au3.dwlnro
    r"[.][A-Z][a-z0-9]{2}[.][a-z]{6}$",
    # Trojan.Win32.323584.cstdm	Trojan.Win32.82471.iokfq
    r"[.][0-9]{5,6}[.][a-z]{5}$",
    # # Trojan.Win32.P2E.4!c	Trojan.Win32.T06.m!c
    # r"[A-Z][A-Z0-9]{2}[.][0-9][!][a-z]",
    # Worm.Nimda!8.F, Trojan.Clicker-Agent!8.13, Downloader.Delf!8.16F, Ransom.Wannacrypt!8.E720
    # Malware.FakePDF/ICON!1.A24C
    # Exploit.CVE-2017-11882/SLT!1.AEE3
    # Downloader.StealthLoader/APT#TA505!1.BD87
    # Malware.FakePIC@CV!1.6AB7	Trojan.Bayrob@VE!1.A37E	Virus.VirLock@EP!1.A247
    # Virus.Parite#dll!1.A144
    # Worm.EternalRocks-02!1.AB01
    r"([-][0-9]{1,2})?([/][[:alnum:]]+)?([#][[:alnum:]]+)?([@][[:alpha:]]+)?![0-9][.][A-F0-9]{1,6}",
    # Trojan.Fuerboos!8.EFC8/N3#91%
    r"[!][0-9][.][0-9A-F]{4}/([A-Z][A-Z0-9])#(100|[1-9][0-9]?)%",
    # Backdoor.Boychi[HT]!1.A08F
    r"\[[A-Z]{2}\][!][0-9][.][A-F0-9]{4}",
    # Exploit.CVE-2012-0158(X)!1.A584
    # TODO Malware.UDM(Delf)!1.6547
    r"\([A-Z][[:alnum:]]*\)[!][0-9][.][A-F0-9]{4}",
    # Win.Malware.Agent1070901705/CRDF-1
    r"[/]CRDF-[0-9]",
    # Win.Adware.Agent-1138899	Win.Trojan.Agent-358135	PUA.Win.Packer.Purebasic-2	Win.Trojan.C99-14
    r"[-][0-9]+",
    # Win.Spyware.58-3
    # Win.Spyware.7826-2
    # Win.Downloader.910-1
    # Win.Spyware.26904-1	Win.Downloader.103202-1
    # Win.Trojan.11313659-10
    r"[.][0-9]{1,8}[-][1-9]?[0-9]",
    # Win.Malware.0051f05f-6957431-0
    # Win.Malware.7958d-8528040-0
    r"[.][a-f0-9]{5,8}[-][0-9]{5,7}[-][1-9]?[0-9]",
    # Win.Trojan.Agent-90809-1	Win.Malware.Autoit-7599063-0
    # Win.Trojan.Agent-6825810-0-6852456-0
    # Win.Trojan.Generic-2-6449654-0
    # Js.Trojan.Agent-1553495-4663817-1
    r"(?:[-][0-9]{5,7})?(?:[-][1-9]?[0-9])?[-][0-9]{5,7}[-][1-9]?[0-9]",
    # BC.Win.Virus.Ransom-9157.A
    r"[-][1-9][0-9]{3}[.][A-Z]",
    # Trojan.Win32.Ges-31.gnlo
    r"[-][1-9][0-9]{1,3}[.][a-z]{4}",
    # Worm.ChineseHacker-2.a
    r"[-][0-9][.][a-z]",
    # Win.Trojan.B-466	Win.Worm.R-97
    r"[.][A-Z]-[1-9][0-9]*",
    # Trojan.CYWATCH-A-000067
    r"[-][A-Z]-[0-9]{6}",
    # Trojan ( 0052c6631 )
    r"\s*\(\s*[a-f0-9]{8,12}\s*\)\s*",
    # Virus.MSWord.Twno.D:Tw
    r"[.][A-Z]:[A-Z][a-z]*",
    # Win.Virus.Sality:1-6335700-1
    r"[:][0-9]-[0-9]{6,8}-[0-9]",
    # Trojan-Heur/Win32.TP.FK6@benBK0db
    r"[.][A-Z0-9]{2}[.][A-Z0-9]@[A-Za-z0-9]{8}",
    # Trojan:Win32/starter.ali1000139
    r"[.]ali[0-9]{6,16}",
    # Virus.20C14C56EB3B96CF	Suspicious:Suspicious.C9C2@17558BEC.mg
    r"[.][A-F0-9][A-F0-9/#@]{11,23}(?:[.]mg)?",
    # Worm/W32.DP-Sytro.Zen.B	Backdoor/SdBot.Gen.c
    r"[.](?:Zen|Gen)[.][A-Za-z]",
]

PREFIXES = [
    r"not-a-vir?us:",
    r"Behav:",
    r"[Hh]eur:",
    r"HEUR:",
    r"UDS:",
    r"[Gg]en:",
    r"modification\sof\s",
    r"possibly\s",
    r"probably\s",
    r"possible-Threat.",
    r"BehavesLike",
    r"Suspicious:",
]


def convert(s, label=_LXL, family=_FAMILY):
    namesuffix = [
        '[.-]based',
    ]

    s = re.escape(s)
    s = s.replace('<Label>', label).replace('<Family>', family).replace('<Kind>', family)
    s = s.replace('<Language>', rf'(?:{LANGS}|{MACROS})').replace('<OS>', str(OSES))
    vg = '|'.join(VARIANTS)
    pz = '|'.join(PREFIXES)
    nz = '|'.join(namesuffix)
    pat = re.compile(rf'^({pz})*{s}({SUFFIXES})?({vg})?({SUFFIXES})?$')
    return pat


class Symbols:
    def states(self):
        pass

    def __str__(self):
        return '(?:{})'.format('|'.join(self.states()))


class StringSymbols(Symbols):
    def __init__(self, s):
        self.name = re.escape(s)
        self._string = s

    def states(self):
        return [self._string]

    def __str__(self):
        return re.escape(self._string)


class RegexSymbols(Symbols):
    def __init__(self, pattern):
        self.pattern = pattern
        super().__init__()

    def states(self):
        return [self.pattern]


class VocabularySymbols(Symbols):
    def __init__(self, vocab):
        self.vocab = vocab
        super().__init__()

    def states(self):
        return [self.vocab.pattern(start=1, end=0)]


class NameSymbols(Symbols):
    patterns = {
        "basic":
            group(
                r"((CVE|Cve|cve|CAN)([_.-]?([0-9]{4})([_.-]?(([0-9]+)[[:alpha:]]*))?)?)",
                r"((?i:MS)([0-9]{2})-?([0-9]{1,3}))",
                r"\w+",
            ),
        "breaks":
            group(
                # Serv-U
                r"[A-Z][a-z]-[A-Z]",
                # VB-Agent
                r"[A-Z]+-[A-Z][[:alnum:]]+",
                # SMS_Attacker
                r"[A-Z]+_[A-Z][[:alnum:]]+",
                # Specikr_macro
                r"[A-Z][[:alpha:]]+_[a-z]+",
                # ExeBundle_2x
                r"[A-Z][[:alpha:]]+_[0-9][[:alpha:]]",
                # BO-plugin-RCR
                r"[A-Z][[:alnum:]]+-[a-z]+-[A-Z][[:alnum:]]+",
                # Clicker-DOTHETUK	Flooder-VB
                r"[A-Z][[:alpha:]]+-[A-Z][[:alpha:]]+",
            )
    }

    def states(self):
        return product(self.patterns.values(), VARIANTS)

    def __str__(self):
        return r"(({})({}|$))".format(self.patterns['basic'], '|'.join(VARIANTS))


class Template:
    def __init__(self, tmpl):
        self.tmpl = tmpl
        self.prefix = None
        self.parts = self.parse()
        self.patterns_used = []
        self.patterns_count = Counter()
        self.all_pattern = self._compile_match_all()

    def parse(self):
        parts = []
        fmt = string.Formatter()
        for i, (literal, field_name, format_spec, conv) in enumerate(fmt.parse(self.tmpl)):
            escaped = re.sub(r'(?<!\\)(?P<sym>[-:./ []])', r'\\\g<sym>', literal)
            parts.append(StringSymbols(escaped))
            if field_name == 'Label':
                parts.append(RegexSymbols(_LXL))
            elif field_name == 'Name':
                parts.append(NameSymbols())
                if self.prefix is None:
                    self.prefix = slice(0, i)

        return parts

    def _compile_match_all(self):
        return re.compile(''.join(r"({})".format("|".join, part.states) for part in self.parts))

    def iterpatterns(self):
        for match in product(*self.parts):
            return re.compile(''.join(match))

    def add_match(self, pattern, existing):
        if not existing:
            self.patterns_used.append(pattern)
        self.patterns_count[pattern] += 1

    def crawl(self, lines):
        patterns = list(self.iterpatterns())

        for line in filter(self.all_pattern.fullmatch, lines):
            for pattern in self.patterns_used:
                if pattern.fullmatch(line):
                    self.add_match(pattern, existing=True)
                    break
            else:
                for i, pattern in enumerate(patterns):
                    if pattern.fullmatch(line):
                        self.add_match(pattern, existing=False)
                        del patterns[i]


def do_converto():
    import string
    Label = None

    Template = lambda s: s
    # PatternTemplate('{Label}.{Label}.{ExtendedFamily}')
    # '{Label}:{Name}'

    # NameTemplate(Label, '/', ExtendedFamily(Label, Label | Name, Variant))
    # [Label, '/', Family(Label | Name, Variant)]

    patterns = [
        Template("{Label}.{ExtName}"),
        Template("{Label}/{ExtName}"),
        Template("{Label}:{Label}/{Name}"),
        Template("{Label}.{Name}"),
        Template("{Label}[{Label}]/{ExtName}"),
        Template("{Label}.[{Family}]{Family}"),
        Template("{Name}"),
    ]

    def parse_template(tmpl):
        fmt = string.Formatter()
        translate = {'Label': None, 'Family': None, 'Variant': None}

        def generator():
            rx = ''
            for literal, field_name, format_spec, conv in fmt.parse(tmpl):
                yield StringSymbols(re.sub(r'(?<!\\)(?P<sym>[-:./ []])', r'\\\g<sym>', literal))
                yield translate[field_name](format_spec)

    def crawl(lines, levels):
        by_head = defaultdict(list)

        for level in levels:
            by_head[level[0]].append(level)

        for sym, levels in by_head.items():
            subset = lines.filter(sym)
            for lvl in levels:
                yield from crawl(subset, lvl)


def do_convert():
    patterns = [
        # convert(ss, family=r'(km_[a-f0-9]+|[0-9a-z]*[A-Z][a-zA-Z0-9._-]+|[a-z]{4,})') for ss in [
        convert(ss) for ss in [
            '<Label>.<Label>.<Label>.<Family>',
            '<Label>.<Label>.<Family>',
            '<Label>:<Label>/<Family>',
            # Backdoor.[OceanLotus]Salgorea!1.C3DC
            '<Label>.[<Family>]<Family>',
            # Trojan[Proxy]/Win32.Coledor
            '<Label>[<Label>]/<Label>.<Family>',
            '<Label>[<Label>]/<Family>',
            # Trojan ( 0fedaa428f )
            '<Label> ( <Variant> )',
            # Nestha.Win32	Alcaul.Win32
            '<Label>/<Label>.<Family>',
            # '<Label>/<Label>',
            '<Label>/<Family>',
            # '<Label>.<Label>',
            '<Label>:<Family>',
            '<Label>.<Family>',
            '<Family>.<OS>',
            '<Family>',
            ##################################
            # # Backdoor.Dropper/Mirai!1.BC48
            # '<Label>.<Label>/<Family>',
            # # Backdoor.Mirai/Linux!1.BC48
            # '<Label>.<Family>/<Label>',
            # 'Suspicious:<Family>',
            # possible-Threat.Joke.SuspectCRC
            # 'possible-Threat.<Label>.<Family>',
            # Trojan:Win32/Fareit.2ed
            # '<Label>-<Label>.<Family>',
            # Trojan-PWS/W32.OnLineGames
            # '<Label>-<Label>/<Label>.<Family>',
            # '<Label><Label>:<Label>/<Family>',
            # Trojan-Dropper.Win32.Multibinder
            # '<Label>-<Label>.<Label>.<Family>',
            'Exp.<Language>.<Family>',
            # TODO Exploit.2011-3544
            # TODO Pixel.Hydra
            # TODO 'possible-Threat.(?Taxon:binomial)'
        ]
    ] + [
        # re.compile(rf'^{_LXL}({_LXL})?:{_LXL}/.+.[a-f0-9]{{8}}$'),
        re.compile(r'^[A-Z][a-z]+(?:\s[[:alpha:]]+)+$'),
        re.compile(r'^Exploit.(?:199[5-9]|20[0-9]{2})-([0-9]+)$'),
    ]

    excluded = [
        re.compile(r'^[\w-]+ \( [0-9A-Fa-f]+ \)'),
        re.compile(r'.*QVM[0-9]+.*'),
        re.compile('.*(?i:eicar).*'),
        re.compile('Error! An Error occurred when scanning a file'),
        re.compile('^[a-z0-9._:?/-]+$'),
    ]

    counter = Counter()

    for engine, _, line in read_family_fixtures():
        if engine == 'Alibaba':
            continue
        elif any(p.match(line) for p in excluded):
            counter['skipped'] += 1
        elif any(p.fullmatch(line) for p in patterns):
            counter['successful'] += 1
        else:
            counter['unsuccessful'] += 1
            print(line)

    print(counter)


do_convert()


def make_all(base_pattern, family):
    prefixes = ['']
    counter = Counter()

    for base_raw in base_pattern:
        base = base_raw.format(LABELS=LABELS)
        matches = defaultdict(list)
        brx = re.compile(rf'^{base}')
        lines = {line for engine, _, line in read_family_fixtures() if brx.match(line)}
        matched = set()
        print('len(lines)=', len(lines))

        patterns = {}

        for prefix, name, variant in product(prefixes, family, VARIANTS):
            nname = rf'{prefix}(?Base)(?Family){variant}'
            pat = re.compile(rf'^{prefix}{base}{name}{variant}$')
            patterns[nname] = pat

        for line in lines:
            for name, pat in patterns.items():
                if pat.fullmatch(line):
                    counter[name] += 1
                    break
                # matches[line].append(nname)
                # matched.add(line)

    pprint(counter)

    # for line, pats in matches.items():
    #     if len(pats) > 1:
    #         print(line, 'Pattners=', pats)

    # for line in (lines - matched):
    #     for prefix, base, name in product(prefixes, base_pattern, family):
    #         baseo = re.compile(rf'^{prefix}{base}({_LIT}[.])?{name}')
    #         if baseo.fullmatch(line):
    #             matched.add(line)
    #             break
    # print(lines - matched)


# make_all(
#     # [r'{LABELS}/', r'(({LABELS})[.]({LABELS}))/'],
#     [r'{_LXL}/', r'{LABELS}[.]', r'({LABELS}[.]{LABELS})/'],
#     [
#         group(
#             r'((CVE|Cve|cve|CAN)([_.-]?([0-9]{4})([_.-]?(([0-9]+)[[:alpha:]]*))?)?)',
#             r'((?i:MS)([0-9]{2})-?([0-9]{1,3}))',
#             r'\w*(?:[a-z][A-Z]|[A-Z][a-z])\w+',
#             r'\d*(?>[A-Z]+[a-z]+\d*){2,5}',
#             str(_LIT),
#             # r'([A-Z]{1,4}-|[0-9]{1,4}-?)?[[:alpha:]]{2,}([0-9]{1,4})?',
#             # r'[A-Z][A-Za-z_-]*[a-zA-Z]',
#             # r'(?:(?:[a-z]{1,2}|20[0-9]{2}|19[789][0-9])[-]?)(?:(?:[A-Z]+[a-z]+)+){i<=4:[A-Z0-9]}',
#             # r'([A-Z]+[a-z]+)+-[A-Z0-9]{1,4}',
#             # r'[a-z][A-Z][a-z]{3,}',
#         ),
#         group(
#             # Basic
#             r"\d*[a-z]?[A-Z][[:alnum:]]+[a-z][[:alnum:]]*",
#             # njRAT
#             r"[a-z]+[A-Z]+",
#             # 4shared
#             r"[0-9][a-z]{4,}",
#             # Serv-U
#             r"[A-Z][a-z]-[A-Z]",
#             # VB-Agent
#             r"[A-Z]+-[A-Z][[:alnum:]]+",
#             # SMS_Attacker
#             r"[A-Z]+_[A-Z][[:alnum:]]+",
#             # Specikr_macro
#             r"[A-Z][[:alpha:]]+_[a-z]+",
#             # ExeBundle_2x
#             r"[A-Z][[:alpha:]]+_[0-9][[:alpha:]]",
#             # BO-plugin-RCR
#             r"[A-Z][[:alnum:]]+-[a-z]+-[A-Z][[:alnum:]]+",
#         ),
#         group(
#             r'[A-Z]+_[A-Z]*[a-z]+',
#             r'[0-9][a-z]{4,}',
#         )
#     ],
# )
