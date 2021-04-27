import regex as re

from ..vocab import FAMILY_ID, LABELS, PLATFORM, SUFFIXES, VARIANT_ID
from ._base import Classification


class Rising(Classification):
    pattern = rf"""^
    (
        ([./-]|^)
        (
            {LABELS}
            | {PLATFORM}
            | BL
            | KL
            | Privacy
            | Andorid
            | Runonce | Runouce
            | Junk
        )
    )*
    (?P<VEID>
        (
            ([./-]|^)
            {FAMILY_ID(
                r'(?# e.x `Trojan.RA-based!8.80`)'
                rf'[[:alpha:]]+(?!{"|".join(filter(lambda s: not s.startswith("-"), SUFFIXES.iteraliases()))})-[[:alpha:]]+',
                r'[a-z][[:alpha:]]{4,}(?=[.])',
                r'[0-9]+[A-Z][[:alpha:]]+',
                r'[A-Z][[:alpha:]]+-([A-Z][[:alpha:]]*|[0-9]+)',
                r'(?# e.x `Malware.Generic[Thunder]!1.A1C4`)'
                r'[A-Z][[:alnum:]]+[(][[:alnum:]]+[)]',
                r'(?# e.x `Worm.Nuj!8.2AD` & `Worm.Oji/Android!8.10B72`)'
                r'[A-Z][[:alpha:]]{1,2}(?=[/!.-])',
                r'(?# e.x `Malware.n!8.FB62`)'
                r'(?<=[.])[a-z](?=!)',
            )}
        )?
        ([/]
            (
                (?&LABELS)
                | {PLATFORM}
                | Source
                | AllInOne
                | SLT
                | APT
            )
        )?
        {VARIANT_ID(
            r'[!][[:alnum:]][.][[:xdigit:]]+',
            r'[.][[:alnum:]][!][[:xdigit:]]+',
            r'[!][[:xdigit:]]{1,5}$',
            r'[.][A-F0-9]{4,}$',
            re.escape('[HT]'),
            r'[#][0-9]{1,3}%',
            r'[!]ET',
            r'[#][A-Z][A-Z0-9]+',
            r'/[A-Z][A-Z0-9]',
            r'[!]tfe',
            r'[@](CV|EP|URL|VE)',
        )}*
    )
    $"""
