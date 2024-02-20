from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID, pattern, VOCABDEF
from ._base import Classification
from . import K7


class ClamAV(Classification):
    __av_name__ = 'ClamAV'
    __patterns__ = (
        VOCABDEF,
        pattern.EICAR_MATCH_ANYWHERE,
        rf"""^
    (Clamav|Urlhaus)?
    (
        ([.]|^)
        (
            (?&PLATFORM)
            | (?&LABELS)
            | Legacy
        )
    )*
    (?P<VEID>
        (
            ([.]|^)
            {FAMILY_ID(r'[a-z]{1,3}[A-Z]{2,4}', r'Blacklist[.]CRT[.][[:xdigit:]]+', r'[[:alnum:]]{3,}(?=-)')}
        )?
        {VARIANT_ID(r'-[0-9]+',
                    r':[0-9]',
                    r'_[0-9]+',
                    r'[.][0-9]+(?=-[0-9])',
                    r'/CRDF(-[[:alnum:]])?',
                    r'[.]Extra_Field')}*
    )
    $""",
        f"^(?&TYPES)\[(?&TYPES)\]/(?&PLATFORM)(?P<VEID>[.]{FAMILY_ID()}{VARIANT_ID()}?)$",
        f"^(?&TYPES)[.](?&TYPES)(?P<VEID>[.]{FAMILY_ID()}(?P<VARIANT>[.][a-z0-9][!][a-z0-9])?)$",
        K7.base_pattern,
    )
