import regex as re

from ..vocab import TYPES
from ._base import Classification


class K7(Classification):
    pattern = rf"^(?P<K7KIND>{TYPES}|[\w-]+)(?P<VEID>\s+\(\s*(?P<VARIANT>[a-f0-9]+)\s*\))?\s*$"

    @property
    def family(self):
        return None

    @property
    def taxon(self) -> str:
        # K7 does not work with family names
        if self.is_EICAR:
            return 'EICAR'

        return self['K7KIND']
