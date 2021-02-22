from ..utils import group
from ._base import VocabRegex

LABELS = VocabRegex.from_resource('LABELS')
LANGS = VocabRegex.from_resource('LANGS')
ARCHIVES = VocabRegex.from_resource('ARCHIVES')
MACROS = VocabRegex.from_resource('MACROS')
OSES = VocabRegex.from_resource('OPERATING_SYSTEMS')
HEURISTICS = VocabRegex.from_resource('HEURISTICS')
OBFUSCATIONS = VocabRegex.from_resource('OBFUSCATIONS')
SUFFIXES = VocabRegex.from_resource('SUFFIXES')
PLATFORM = group(OSES, ARCHIVES, MACROS, LANGS, HEURISTICS, OBFUSCATIONS)

TYPES = group(f'{LABELS}(-?(?&LABELS))?', PLATFORM, name='TYPES')


def VARIANT_ID(*extra):
    return group(
        format(SUFFIXES, '-g:-i'),
        *extra,
        r'[.][A-Z]{1,3}',
        r'[.][a-z0-9]{1,8}',
        r'[.][A-Z][a-z][a-z]',
        name='VARIANT'
    )


CVE_PATTERN = r'(?P<exploit>(?P<CVE>(CVE|Cve|cve)(*SKIP)([-_]?(?P<CVEYEAR>[0-9]{4})([-_]?((?P<CVENTH>[0-9]+)[[:alpha:]]*))?)?))'
MS_BULLETIN_PATTERN = r'(?P<exploit>(?P<microsoft_security_bulletin>MS(?P<MSSEC_YEAR>[0-9]{2})-(?P<MSSECNTH>[0-9]{1,3})))'


def FAMILY_ID(
    *extra,
    CVE=CVE_PATTERN,
    MSSEC=MS_BULLETIN_PATTERN,
    named=[HEURISTICS, OBFUSCATIONS],
    standard=[
        # e.x `iBryte` & `9Fire`
        r'[0-9a-z]{1,2}[A-Z][a-zA-Z]{2,}',
        # e.x `Hello_World99` & `Emotet`
        r'[A-Z][a-zA-Z0-9_]{3,}',
    ],
):
    return group(
        CVE,
        MSSEC,
        group(
            *map(format, named),
            *extra,
            *standard,
            name='FAMILY',
        ),
    )
