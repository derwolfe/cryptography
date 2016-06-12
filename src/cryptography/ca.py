# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function


import datetime
import uuid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa
from cyptography import x509

# This module is responsible for the creation and management of certificates
# for a home grown CA. It is intended to provide a pythonic interface similar
# to easyrsa (https://github.com/OpenVPN/easy-rsa/tree/master/easyrsa3)
# This should be able to:
# 1. generate CA key, certificates
# 2. generate server keys, certificates
# 3. generate client keys, certificates
# 4. generate revocation requests for certificates issued by the CA.
# 5. keep a database of currently issued and revoked certificates

# Early ideas
# 1. Testing should probably include the ability to keep a store in memory,
#   instead of requiring that data be written out.


def generate_private_key(public_exponent=65537,
                         key_type=u'rsa',
                         key_size=4096):
    return rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend())


def generate_ca_certs(ca_name, now, days_until_expiration):
    ca_key = generate_private_key()
    ca_name = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, ca_name)])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .not_valid_before(now - datetime.timedelta(seconds=3600))
        .not_valid_after(now + datetime.timedelta(days=days_until_expiration))
        .public_key(ca_key.public_key())
        .serial_number(int(uuid.uuid4()))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                ca_key.public_key()),
            critical=False)
        .sign(
            private_key=ca_key,
            algorithm=SHA256(),
            backend=default_backend()))
    return ca_key, ca_cert
