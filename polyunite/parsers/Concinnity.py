from ..vocab import LABELS, PLATFORM
from ._base import Classification


class Concinnity(Classification):
    pattern = rf"""^
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
    $"""

    @property
    def name(self):
        return self.taxon
