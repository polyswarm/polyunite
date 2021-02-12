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
            {FAMILY_ID(r'Blacklist[.]CRT[.][[:xdigit:]]+', '[A-Z][[:alpha:]]+', r'[A-Z0-9][[:alnum:]]+(?=-)')}
        )?
        {VARIANT_ID(r'-[0-9]+',
                    r':[0-9]',
                    r'[.][0-9]+(?=-[0-9])',
                    r'/CRDF(-[[:alnum:]])?',
                    r'[.]Extra_Field')}*
    )
    $"""
