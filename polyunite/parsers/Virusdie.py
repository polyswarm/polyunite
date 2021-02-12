from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID
from ._base import Classification


class Virusdie(Classification):
    pattern = rf"""^
    (
        (^|[.-])
        {PLATFORM}|{LABELS}
    )*
    (?P<VEID>
        (
            (^|[.])
            (
                {FAMILY_ID()}
                | .+
            )
        )?
        {VARIANT_ID()}*
    )
    $"""
