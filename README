Python library to read KeePass password database files.
=======================================================

Features:
========
 - contains a pure python library to read KeePass 1.x database format (.kdb)
 - CLI client
  - tab completion
  - automatic database closing and clearing of screen

Installation:
=============
    * install python-dev or equivalent (apt-get install python-dev)
    * run python setup.py install

Usage:
======
    run bin/py-keepassx

    Type 'help' for help.

Typical session:

    [py-keepassx]: open ~/keys.kdb
    Password:
    Opened.
    [py-keepassx]: ls
    + Internet
    + Backup
    [py-keepassx]: cd Internet
    [py-keepassx]: ls
    x site1
    x site2
    [py-keepassx]: cat site1
    site1
    --

    url:     https://www.example.com
    user:    foo@example.com
    pass:    <<secret>>
    comment:
    [py-keepassx]: passwd site1
    passwd: foobar
    [py-keepassx]: clear
    [py-keepassx]: quit
    Bye.
