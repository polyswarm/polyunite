from ._base import VocabRegex
from ..utils import group

LABELS = VocabRegex.from_resource('LABELS')
LANGS = VocabRegex.from_resource('LANGS')
ARCHIVES = VocabRegex.from_resource('ARCHIVES')
MACROS = VocabRegex.from_resource('MACROS')
OSES = VocabRegex.from_resource('OPERATING_SYSTEMS')
HEURISTICS = VocabRegex.from_resource('HEURISTICS')
OBFUSCATIONS = VocabRegex.from_resource('OBFUSCATIONS')
SUFFIXES = VocabRegex.from_resource('SUFFIXES')
PLATFORM = group(OSES, ARCHIVES, MACROS, LANGS, HEURISTICS, OBFUSCATIONS)

def VARIANT_ID(*extra):
    return group(
        format(SUFFIXES, '-g:-i'),
        *extra,
        r'[.][A-Z]{1,3}',
        r'[.][a-z0-9]{1,8}',
        r'[.][A-Z][a-z][a-z]',
        name='VARIANT'
    )

CVE_PATTERN = r'(?P<CVE>(CVE|Cve|cve)([-_]?(?P<CVEYEAR>[0-9]{4})([-_]?((?P<CVENTH>[0-9]+)[[:alpha:]]*))))'

def FAMILY_ID(*extra):
    return group(
        CVE_PATTERN,
        r'MS[0-9][0-9]-[0-9]{1,6}',  # Microsoft exploit
        format(HEURISTICS),
        format(OBFUSCATIONS),
        *extra,
        r'CVE(-[0-9]{4})?(?![0-9.-_])',
        r'[0-9a-z]{1,2}[A-Z][a-zA-Z]{2,}',
        r'[A-Z][a-zA-Z0-9_]{3,}',
        name='FAMILY'
    )
