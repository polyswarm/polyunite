from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID, pattern
from ._base import Classification


class Tachyon(Classification):
    __av_name__ = 'Tachyon'
    # https://tachyonlab.com/en/main_name/main_name.html
    __patterns__ = (
        pattern.EICAR_MATCH_ANYWHERE,
        rf"""^
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
        {VARIANT_ID(r'[.][0-9]+', r'[.][A-Za-z0-9]')}{{,2}}
    )$""",
    )
