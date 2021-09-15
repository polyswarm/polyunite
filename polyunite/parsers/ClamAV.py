from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID, pattern
from ._base import Classification


class ClamAV(Classification):
    __av_name__ = 'ClamAV'
    __patterns__ = (
        pattern.EICAR_MATCH_ANYWHERE,
        rf"""^
    (Clamav|Urlhaus)?
    (
        ([.]|^)
        (
            {PLATFORM}
            | {LABELS}
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
    )
