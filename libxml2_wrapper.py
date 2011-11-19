#!/usr/bin/env python

import libxml2

class LibXML2ParsedDocument(object):
    def __init__(self, xml):
        doc = libxml2.parseMemory(xml, len(xml))
        if doc is None or doc.getRootElement() is None:
            raise RuntimeError('unable to parse document')
        self.doc = doc

    def __enter__(self):
        return self.doc

    def __exit__(self, type, value, traceback):
        self.doc.freeDoc()
