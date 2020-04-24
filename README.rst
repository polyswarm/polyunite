=========
polyunite
=========

polyunite parses a antimalware vendor's classification strings into a unified format with logical interpolation of other features.


Supported:
--------

- Alibaba
- ClamAV
- DrWeb
- Ikarus
- Jiangmin
- K7
- Lionic
- NanoAV
- Qihoo360
- QuickHeal
- Rising
- Virusdie
- URLHaus


Features
--------

To view a sample of how each ``polyunite`` breaks down each classification string, run::

  python tests/colorize.py

The output is color-coded by malware family feature (e.g `label`, `family name`, `variant id`, etc.)

.. image:: https://raw.githubusercontent.com/polyswarm/polyunite/master/docs/images/colorized.png
