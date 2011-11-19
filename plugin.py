#!/usr/bin/env python

from suds.plugin import MessagePlugin
from lxml import etree
from suds.bindings.binding import envns
from suds.wsse import wsuns, dsns, wssens
from libxml2_wrapper import LibXML2ParsedDocument, XmlSecSignatureContext, init_xmlsec, deinit_xmlsec
from base64 import b64encode
try:
	from hashlib import sha1
except ImportError:
	import sha1
try:
	from cStringIO import StringIO
except ImportError:
	from StringIO import StringIO

import sys
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
	def __init__(self):
		init_xmlsec()

	def sending(self, context):
		try:
			env = etree.fromstring(context.envelope)
			(body,) = BODY_XPATH(env)
			body.set(ns_id('Id', wsuns), SIGNED_ID)
			security = ensure_security_header(env)
			signature = etree.SubElement(security, ns_id('Signature', dsns))
			signed_info = etree.SubElement(signature, ns_id('SignedInfo', dsns))

			etree.SubElement(signed_info, ns_id('CanonicalizationMethod', dsns),
					{'Algorithm': C14N})
			etree.SubElement(signed_info, ns_id('SignatureMethod', dsns),
					{'Algorithm': 'http://www.w3.org/2000/09/xmldsig#dsa-sha1'})

			reference = etree.SubElement(signed_info, ns_id('Reference', dsns),
					{'URI': '#{0}'.format(SIGNED_ID)})
			transforms = etree.SubElement(reference, ns_id('Transforms', dsns))
			etree.SubElement(transforms, ns_id('Transform', dsns),
					{'Algorithm': C14N})
			etree.SubElement(reference, ns_id('DigestMethod', dsns),
				{'Algorithm': 'http://www.w3.org/2000/09/xmldsig#sha1'})
			etree.SubElement(reference, ns_id('DigestValue', dsns))

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
	
	def get_signature(self, envelope):
		with LibXML2ParsedDocument(envelope) as doc:
			root = doc.getRootElement()
			xmlsec.addIDs(doc, root, ['Id'])
			signNode = xmlsec.findNode(root, xmlsec.NodeSignature, xmlsec.DSigNs)
			with XmlSecSignatureContext() as dsig_ctx:
				dsig_ctx.signKey = self.get_key()
				if dsig_ctx.sign(signNode) < 0:
					raise RuntimeError('signature failed')
				return doc.serialize()
	
	def get_key(self):
		key = xmlsec.cryptoAppKeyLoad('../keys/privkey.pem', xmlsec.KeyDataFormatPem, # XXX
				None, None, None)
		if key is None:
			raise RuntimeError('failed to load private pem key')
		return key
	
	def __del__(self):
		deinit_xmlsec()

def ensure_security_header(env):
	(header,) = HEADER_XPATH(env)
	security = SECURITY_XPATH(header)
	if security:
		return security[0]
	else:
		return etree.SubElement(header, ns_id('Security', wssens),
				{ns_id('mustUnderstand', envns): '1'}, NSMAP)
