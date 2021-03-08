#!/usr/bin/env python3
"""Small test script for CDS verification"""

from OpenSSL.crypto import (
    load_certificate,
    FILETYPE_ASN1,
    FILETYPE_PEM,
    X509Store,
    X509StoreContext,
)

store = X509Store()
certs = {
    "csca_Estonia_2007.cer": FILETYPE_PEM,
    "csca_Estonia_2007-2009-link.cer": FILETYPE_PEM,
    "csca_Estonia_2009.crt": FILETYPE_ASN1,
    "csca_Estonia_2009-2012-link.cer": FILETYPE_PEM,
    "csca_Estonia_2012.cer": FILETYPE_ASN1,
    "csca_Estonia_2012-2015-link.crt": FILETYPE_ASN1,
    "csca_Estonia_2015.cer": FILETYPE_ASN1,
    "csca_Estonia_2015-2016-link.crt": FILETYPE_ASN1,
    "csca_Estonia_2016.cer": FILETYPE_ASN1,
    "csca_Estonia_2016-2019-link.crt": FILETYPE_ASN1,
    "csca_Estonia_2019.cer": FILETYPE_ASN1,
    "csca_Estonia_2019-2020-link.der": FILETYPE_ASN1,
    "csca_Estonia_2020.der": FILETYPE_ASN1,
}

for fn, ft in certs.items():
    with open("CSCA_certs/" + fn, "rb") as infile:
        CSCA = load_certificate(ft, infile.read())
    store.add_cert(CSCA)

with open("CDS", "rb") as infile:
    CDS = load_certificate(FILETYPE_ASN1, infile.read())

store_ctx = X509StoreContext(store, CDS)

if store_ctx.verify_certificate() is None:
    print("[+] Document Signer Certificate is signed by a CSCA certificate")