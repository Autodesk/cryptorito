[![Build Status](https://travis-ci.org/Autodesk/cryptorito.svg?branch=master)](https://travis-ci.org/Autodesk/aomi)[![PyPI](https://img.shields.io/pypi/v/cryptorito.svg)](https://pypi.python.org/pypi/cryptorito)[![Maintenance](https://img.shields.io/maintenance/yes/2017.svg)]()

# Cryptorito: Some Wrapped Up Crypto Bits

This is a helper library for some of the Vault related tooling we are developing at [Autodesk](https://autodesk.github.io/). It provides access to required [GPG](https://www.gnupg.org/) and [Keybase](https://keybase.io/) functionality in a MIT licensed Python module.

As of now, it allows the following

* Fetch a key from Keybase
* Import a GPG key into our key store
* Encrypt against a set of of keys
* Decrypt with our own private key

We use this as part of the [aomi](https://autodesk.github.io/aomi) project.

# Contribution Guidelines

* This project operates under a [Code of Conduct](https://github.com/autodesk/cryptorito/blob/master/code_of_conduct).
* Changes are welcome via pull request!
* Please use informative commit messages and pull request descriptions.
* Please remember to update the documentation if needed.
* Please keep style consistent. This means PEP8 and pylint compliance at a minimum.
* Please add unit tests.

If you have any questions, please feel free to contact <jonathan.freedman@autodesk.com>

# Errata

The Code of Conduct is version 1.4 of the [Contributor Covenant](http://contributor-covenant.org/).
