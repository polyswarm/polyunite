#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

requirements = [ ]

setup_requirements = ['pytest-runner', 'regex']

test_requirements = ['pytest', ]

setup(
    author="Zephyr Pellerin",
    author_email='zp@polyswarm.io',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    entry_points={
        'console_scripts': [ 'main=polyunite.polyunite:main' ]
    },
    description="polyunite parses a variety of antimalware vendor's classification strings",
    install_requires=requirements,
    long_description=readme,
    include_package_data=True,
    keywords='polyunite',
    name='polyunite',
    packages=find_packages(include=['polyunite']),
    package_data={'polyunite': ['vocabs/*']},
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/zv/polyunite',
    version='0.1.0',
    zip_safe=False,
)
