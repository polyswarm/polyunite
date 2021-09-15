from ..utils import group
from ._base import VocabRegex
from .pattern import CVE_PATTERN, MS_BULLETIN_PATTERN, EICAR_GROUP_NAME

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

VOCABDEF = rf'''
(?(DEFINE)
    {LABELS}
    {LANGS}
    {ARCHIVES}
    {MACROS}
    {OSES}
    {HEURISTICS}
    {OBFUSCATIONS}
    (?P<PLATFORM>(?&OPERATING_SYSTEMS)|(?&ARCHIVES)|(?&MACROS)|(?&LANGS)|(?&HEURISTICS)|(?&OBFUSCATIONS))
    (?P<TYPES>(?:(?&LABELS)(-?(?&LABELS))?)|(?&PLATFORM))
)
'''

def VARIANT_ID(*extra):
    return group(
        format(SUFFIXES, '-g:-i'),
        *extra,
        r'[.][A-Z]{1,3}',
        r'[.][a-z0-9]{1,8}',
        r'[.][A-Z][a-z][a-z]',
        name='VARIANT'
    )


def FAMILY_ID(
    *extra,
    CVE=CVE_PATTERN,
    MSSEC=MS_BULLETIN_PATTERN,
    named=[HEURISTICS, OBFUSCATIONS],
    standard=[
        '[A-Z][a-z]{2}',
        # e.x `Hello_World99` & `Emotet`
        r'([0-9]{1,3})?[A-Z]{4,8}([0-9]{1,3})?',
        # Handle common year prefixes, like `2008Virus`
        r'(?!.{1,3}($|[.!#@]))'
        r'((?:20[012]\d|19[89]\d)(?=[A-Z]))?'
        # Handle special prefixes, like `iPhone`, `X-Connect` or `eWorm`
        r'(?:([a-z]{1,2}|[iIeExX]-)(?=[A-Z]))?'
        # Handle up to 5 capitalized words, optionally separated by '-' or '_'
        r'(?:'
        r'(?:[A-Z]{1,5}|\d{1,2})[a-z]+'
        r'(?:'
            r'(?:[A-Z]{1,5}[a-z]+){1,4}'
            r'|(?:_[A-Z]{1,4}[a-z]+){1,2}'
            r'|(?:-[A-Z]{1,4}[a-z]+){1,2}'
        r')?'
        r'){i<=2:\d}'
        # Handle upper-case suffixes like `FakeAV`
        r'((?:[0-9]{1,3}|[A-Z]{1,3})(?![a-zA-Z0-9]))?'
        r'((?<=[a-zA-Z0-9])_[a-z]+)?',
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


'<TITLE> ( <HEX> )'
