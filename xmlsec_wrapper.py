#!/usr/bin/env python

import libxml2, xmlsec

class XmlSecSignatureContext(object):
    def __init__(self):
        self.dsig_ctx = xmlsec.DSigCtx()
        if self.dsig_ctx is None:
            raise RuntimeError('failed to create signature context')

    def __enter__(self):
        return self.dsig_ctx

    def __exit__(self, type, value, traceback):
        self.dsig_ctx.destroy()

def init_xmlsec():
    libxml2.initParser()
    libxml2.substituteEntitiesDefault(1)
    if xmlsec.init() < 0:
        raise RuntimeError('xmlsec initialization failed')
    if xmlsec.checkVersion() != 1:
        raise RuntimeError('loaded xmlsec library version is not compatible')
    if xmlsec.cryptoAppInit(None) < 0:
        raise RuntimeError('crypto initialization failed')
    if xmlsec.cryptoInit() < 0:
        raise RuntimeError('xmlsec-crypto initialization failed')

def deinit_xmlsec():
    xmlsec.cryptoShutdown()
    xmlsec.cryptoAppShutdown()
    xmlsec.shutdown()
    libxml2.cleanupParser()
