from ..vocab import FAMILY_ID, LABELS, VARIANT_ID
from ._base import Classification


class URLHaus(Classification):
    pattern = rf"""^
    {LABELS}?
    (?P<VEID>
        (
            (^|[.])
            {FAMILY_ID()}
        )?
        {VARIANT_ID()}*
    )
    $"""
