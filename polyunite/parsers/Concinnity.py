from ..vocab import LABELS, PLATFORM, pattern
from ._base import Classification


class Concinnity(Classification):
    __av_name__ = 'Concinnity'
    __patterns__ = (
        pattern.EICAR_MATCH_ANYWHERE,
        rf"""^
    (([.]|^)
     (
        {PLATFORM}
        | {LABELS}
        | (
            (?P<CRYPTOKIND>btc|eth|zec|xmr)
            ([.](?P<CRYPTO_ADDRESS>[A-Za-z0-9+/]+))?
          )
     )
    )*
    $""",
    )

    @property
    def name(self):
        return self.taxon
