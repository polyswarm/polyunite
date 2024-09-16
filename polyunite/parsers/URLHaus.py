from ..vocab import FAMILY_ID, LABELS, VARIANT_ID, pattern
from ._base import Classification


class URLHaus(Classification):
    __av_name__ = 'URLHaus'
    __patterns__ = (
        pattern.EICAR_MATCH_ANYWHERE,
        rf"""^
    {LABELS}?
    (?P<VEID>
        (
            (^|[.])
            {FAMILY_ID()}
        )?
        {VARIANT_ID()}*
    )
    $""",
    )
