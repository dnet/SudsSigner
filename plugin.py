#!/usr/bin/env python

from __future__ import with_statement
from suds.plugin import MessagePlugin
from lxml import etree
from suds.bindings.binding import envns
from suds.wsse import wsuns, dsns, wssens
from libxml2_wrapper import LibXML2ParsedDocument
from xmlsec_wrapper import XmlSecSignatureContext, init_xmlsec, deinit_xmlsec
from SignatureMethods import DSA, RSA
from OpenSSL import crypto

import xmlsec

def lxml_ns(suds_ns):
    return dict((suds_ns,))

def ns_id(tagname, suds_ns):
    return '{{{0}}}{1}'.format(suds_ns[1], tagname)

LXML_ENV = lxml_ns(envns)
BODY_XPATH = etree.XPath('/SOAP-ENV:Envelope/SOAP-ENV:Body', namespaces=LXML_ENV)
HEADER_XPATH = etree.XPath('/SOAP-ENV:Envelope/SOAP-ENV:Header', namespaces=LXML_ENV)
SECURITY_XPATH = etree.XPath('/wsse:Security', namespaces=lxml_ns(wssens))
SIGNED_ID = 'suds-signed'
C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#'
NSMAP = dict((dsns, wssens, wsuns))

class SignerPlugin(MessagePlugin):
    def __init__(self, keyfile, keytype=None, pwd=None, pwdCallback=None,
            pwdCallbackCtx=None):
        init_xmlsec()
        self.keyfile = keyfile
        self.pwd = pwd
        self.pwdCallback = pwdCallback
        self.pwdCallbackCtx = pwdCallbackCtx
        self.load_keyfile()
        self.keytype = self.handle_keytype(keytype)

    def load_keyfile(self):
        with file(self.keyfile, 'rb') as keyfile:
            self.cert = crypto.load_certificate(crypto.FILETYPE_PEM,
                    keyfile.read())
        self.signer_key = xmlsec.cryptoAppKeyLoad(self.keyfile,
                xmlsec.KeyDataFormatPem, self.pwd, self.pwdCallback,
                self.pwdCallbackCtx)
        if self.signer_key is None:
            raise RuntimeError('failed to load private pem key')

    def handle_keytype(self, keytype):
        if keytype is None:
            return self.detect_keytype()
        elif any(isinstance(keytype, t) for t in (str, unicode)):
            return keytype
        else:
            raise ValueError('keytype must be a string or None')

    def detect_keytype(self):
        algo = self.cert.get_signature_algorithm()
        if algo.startswith('dsa'):
            return DSA
        if algo.startswith('rsa'):
            return RSA
        raise ValueError('unknown keytype')

    def sending(self, context):
        try:
            env = etree.fromstring(context.envelope)
            (body,) = BODY_XPATH(env)
            body.set(ns_id('Id', wsuns), SIGNED_ID)
            security = ensure_security_header(env)
            signature = etree.SubElement(security, ns_id('Signature', dsns))
            self.append_signed_info(signature)

            etree.SubElement(signature, ns_id('SignatureValue', dsns))

            key_info = etree.SubElement(signature, ns_id('KeyInfo', dsns))
            sec_token_ref = etree.SubElement(key_info,
                    ns_id('SecurityTokenReference', wssens))
            x509_data = etree.SubElement(sec_token_ref, ns_id('X509Data', dsns))
            x509_issuer_serial = etree.SubElement(x509_data,
                    ns_id('X509IssuerSerial', dsns))
            x509_issuer_name = etree.SubElement(x509_issuer_serial,
                    ns_id('X509IssuerName', dsns))
            x509_issuer_name.text = 'CN=Arena'
            x509_serial_number = etree.SubElement(x509_issuer_serial,
                    ns_id('X509SerialNumber', dsns))
            x509_serial_number.text = '1321699512'

            context.envelope = self.get_signature(etree.tostring(env))
        except Exception as e:
            print e
            raise

    def append_signed_info(self, signature):
        signed_info = etree.SubElement(signature, ns_id('SignedInfo', dsns))
        set_algorithm(signed_info, 'CanonicalizationMethod', C14N)
        set_algorithm(signed_info, 'SignatureMethod', self.keytype)
        reference = etree.SubElement(signed_info, ns_id('Reference', dsns),
                {'URI': '#{0}'.format(SIGNED_ID)})
        transforms = etree.SubElement(reference, ns_id('Transforms', dsns))
        etree.SubElement(transforms, ns_id('Transform', dsns),
                {'Algorithm': C14N})
        set_algorithm(reference, 'DigestMethod',
                'http://www.w3.org/2000/09/xmldsig#sha1')
        etree.SubElement(reference, ns_id('DigestValue', dsns))

    def get_signature(self, envelope):
        with LibXML2ParsedDocument(envelope) as doc:
            root = doc.getRootElement()
            xmlsec.addIDs(doc, root, ['Id'])
            signNode = xmlsec.findNode(root, xmlsec.NodeSignature, xmlsec.DSigNs)
            with XmlSecSignatureContext() as dsig_ctx:
                dsig_ctx.signKey = self.signer_key
                if dsig_ctx.sign(signNode) < 0:
                    raise RuntimeError('signature failed')
                return doc.serialize()

    def __del__(self):
        deinit_xmlsec()

def set_algorithm(parent, name, value):
    etree.SubElement(parent, ns_id(name, dsns), {'Algorithm': value})

def ensure_security_header(env):
    (header,) = HEADER_XPATH(env)
    security = SECURITY_XPATH(header)
    if security:
        return security[0]
    else:
        return etree.SubElement(header, ns_id('Security', wssens),
                {ns_id('mustUnderstand', envns): '1'}, NSMAP)
