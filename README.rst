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

  $ make report

The output is color-coded by malware family feature (e.g `label`, `family name`, `variant id`, etc.)

.. image:: https://raw.githubusercontent.com/polyswarm/polyunite/master/docs/images/colorized.png


Debugging and Testing
~~~~~~~

You can show the underlying regular expressions built for each engine with::

    $ make patterns-report

If you've added a new engine or made breaking changes to an existing engine,
you'll need to rebuild the fixture archive (which you should make sure is
correct before pushing)::

    $ make result-fixtures
