from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID
from ._base import Classification


class ClamAV(Classification):
    pattern = rf"""^
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
    $"""
