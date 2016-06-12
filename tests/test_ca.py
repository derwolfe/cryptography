# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import datetime

from cryptography.ca import generate_private_key, generate_ca_certs


def test_generate_ca_certs():
    ca_key, ca_cert = generate_ca_certs(
        ca_name=u'ca-best-ca',
        now=datetime.now(),
        days_until_expiration=20)
    assert ca_key is None
    assert ca_cert is None


def test_generate_private_key():
    assert generate_private_key() is not None
