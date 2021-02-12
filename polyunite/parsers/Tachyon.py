from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID
from ._base import Classification


class Tachyon(Classification):
    # https://tachyonlab.com/en/main_name/main_name.html
    pattern = rf"""^
    (
        (^|[-])
        ({PLATFORM}|{LABELS})
    )+
    (/{PLATFORM})
    (?P<VEID>
        (
            [.]
            {FAMILY_ID(r'[A-Z]{2}[-][A-Z][[:alpha:]]+')}
        )
        {VARIANT_ID(r'[.][0-9]+')}{{,2}}
    )$"""
