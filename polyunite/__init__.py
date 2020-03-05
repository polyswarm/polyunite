# -*- coding: utf-8 -*-
__author__ = """Zephyr Pellerin"""
__email__ = 'zp@polyswarm.io'
__version__ = '0.1.0'

from .polyunite import engines
from string import whitespace, punctuation, ascii_lowercase, ascii_uppercase


def parse(
    name, classification: str, tr=str.maketrans(ascii_uppercase, ascii_lowercase, whitespace + punctuation)
):
    return engines.get(name.translate(tr), lambda c: None)(classification)


__all__ = ['parse', 'engines']
