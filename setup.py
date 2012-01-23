#!/usr/bin/env python

from setuptools import setup

setup(
    name="py-keepassx",
    version="0.1-dev",
    description="Python library to read KeePassX password database files.",
    author="Tomi Oikarinen",
    author_email="tomi.oikarinen@iki.fi",
    license="GNU General Public License",
    packages=[
        "pykeepassx",
    ],
    scripts=[
        "bin/py-keepassx",
    ],
    install_requires=[
        "pycrypto>=2.5"
    ],
)
