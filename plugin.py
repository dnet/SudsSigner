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
from uuid import uuid4

import xmlsec

def lxml_ns(suds_ns):
    return dict((suds_ns,))

def ns_id(tagname, suds_ns):
    return '{{{0}}}{1}'.format(suds_ns[1], tagname)

LXML_ENV = lxml_ns(envns)
BODY_XPATH = etree.XPath('/SOAP-ENV:Envelope/SOAP-ENV:Body', namespaces=LXML_ENV)
HEADER_XPATH = etree.XPath('/SOAP-ENV:Envelope/SOAP-ENV:Header', namespaces=LXML_ENV)
SECURITY_XPATH = etree.XPath('wsse:Security', namespaces=lxml_ns(wssens))
TIMESTAMP_XPATH = etree.XPath('wsu:Timestamp', namespaces=lxml_ns(wsuns))
C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#'
XMLDSIG_SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1'
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
        env = etree.fromstring(context.envelope)
        (body,) = BODY_XPATH(env)
        queue = SignQueue()
        queue.push_and_mark(body)
        security = ensure_security_header(env, queue)
        self.insert_signature_template(security, queue)
        context.envelope = self.get_signature(etree.tostring(env))

    def insert_signature_template(self, security, queue):
        signature = etree.SubElement(security, ns_id('Signature', dsns))
        self.append_signed_info(signature, queue)
        etree.SubElement(signature, ns_id('SignatureValue', dsns))
        self.append_key_info(signature)

    def append_signed_info(self, signature, queue):
        signed_info = etree.SubElement(signature, ns_id('SignedInfo', dsns))
        set_algorithm(signed_info, 'CanonicalizationMethod', C14N)
        set_algorithm(signed_info, 'SignatureMethod', self.keytype)
        queue.insert_references(signed_info)

    def append_key_info(self, signature):
        key_info = etree.SubElement(signature, ns_id('KeyInfo', dsns))
        sec_token_ref = etree.SubElement(key_info,
                ns_id('SecurityTokenReference', wssens))
        x509_data = etree.SubElement(sec_token_ref, ns_id('X509Data', dsns))
        x509_issuer_serial = etree.SubElement(x509_data,
                ns_id('X509IssuerSerial', dsns))
        x509_issuer_name = etree.SubElement(x509_issuer_serial,
                ns_id('X509IssuerName', dsns))
        x509_issuer_name.text = ', '.join(
                '='.join(c) for c in self.cert.get_issuer().get_components())
        x509_serial_number = etree.SubElement(x509_issuer_serial,
                ns_id('X509SerialNumber', dsns))
        x509_serial_number.text = str(self.cert.get_serial_number())

    def get_signature(self, envelope):
        with LibXML2ParsedDocument(envelope) as doc:
            root = doc.getRootElement()
            xmlsec.addIDs(doc, root, ['Id'])
            signNode = xmlsec.findNode(root, xmlsec.NodeSignature, xmlsec.DSigNs)
            with XmlSecSignatureContext(self) as dsig_ctx:
                if dsig_ctx.sign(signNode) < 0:
                    raise RuntimeError('signature failed')
                return doc.serialize()

    def __del__(self):
        deinit_xmlsec()

class SignQueue(object):
    WSU_ID = ns_id('Id', wsuns)
    DS_DIGEST_VALUE = ns_id('DigestValue', dsns)
    DS_REFERENCE = ns_id('Reference', dsns)
    DS_TRANSFORMS = ns_id('Transforms', dsns)

    def __init__(self):
        self.queue = []

    def push_and_mark(self, element):
        unique_id = get_unique_id()
        element.set(self.WSU_ID, unique_id)
        self.queue.append(unique_id)

    def insert_references(self, signed_info):
        for element_id in self.queue:
            reference = etree.SubElement(signed_info, self.DS_REFERENCE,
                    {'URI': '#{0}'.format(element_id)})
            transforms = etree.SubElement(reference, self.DS_TRANSFORMS)
            set_algorithm(transforms, 'Transform', C14N)
            set_algorithm(reference, 'DigestMethod', XMLDSIG_SHA1)
            etree.SubElement(reference, self.DS_DIGEST_VALUE)

def get_unique_id():
    return 'id-{0}'.format(uuid4())

def set_algorithm(parent, name, value):
    etree.SubElement(parent, ns_id(name, dsns), {'Algorithm': value})

def ensure_security_header(env, queue):
    (header,) = HEADER_XPATH(env)
    security = SECURITY_XPATH(header)
    if security:
        for timestamp in TIMESTAMP_XPATH(security[0]):
            queue.push_and_mark(timestamp)
        return security[0]
    else:
        return etree.SubElement(header, ns_id('Security', wssens),
                {ns_id('mustUnderstand', envns): '1'}, NSMAP)
