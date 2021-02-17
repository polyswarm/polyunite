#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    author="Polyswarm Developers",
    author_email='developers@polyswarm.io',
    classifiers=[
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    entry_points={
        'console_scripts': [ 'main=polyunite.polyunite:main' ]
    },
    description="polyunite parses a variety of antimalware vendor's classification strings",
    install_requires=[
        'regex~=2020.11.13',
        'rapidfuzz~=1.0.0',
    ],
    long_description='file: README.rst',
    long_description_content_type='rst',
    include_package_data=True,
    keywords='polyunite',
    name='polyunite',
    packages=find_packages(include=['polyunite', 'polyunite.*']),
    package_data={'polyunite': ['vocab/*.json']},
    setup_requires=[
        'pytest-runner',
    ],
    test_suite='tests',
    tests_require=[
        'pytest',
    ],
    url='https://github.com/polyscore/polyunite',
    version='1.2.1',
    zip_safe=True,
)
