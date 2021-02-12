from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID
from ._base import Classification


class QuickHeal(Classification):
    pattern = rf"""^
    (
        ([./]|^)
        ({PLATFORM}|{LABELS}(?&LABELS)?|Cmd|PIF|alware)
    )*
    (?P<VEID>
        (?![.]S[[:xdigit:]]+\b)
        (
            ([./]|^)
            {FAMILY_ID(
                r'[0-9]+[A-Z][a-z]+',
                r'[A-Z][a-z]+[0-9]+',
            )}
        )?
        {VARIANT_ID(
            r'[.]HTML[.][A-Z]',
            r'[-][A-Z]',
            r'[.][A-Z][[:xdigit:]]+$',
            r'[.][A-Z]{1,2}[0-9]{1,2}',
            r'[.][a-z0-9]{2,3}+'
            )}{{,2}}
    )
    $"""
