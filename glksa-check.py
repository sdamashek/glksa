#!/usr/bin/python

import sys
import os
import xml.dom.minidom
from functools import reduce
import gzip
import re

import portage
from portage.output import *
from io import StringIO
from gentoolkit.glsa import *
from portage.versions import vercmp

from getopt import getopt, GetoptError

kv = re.compile(r'#.*?((?:\d+\.)+(?:\d+)).*Kernel Configuration')
kc = re.compile(r'[\n\^]CONFIG_([^=\n^]+)=([^\n$]+)')
opMapping = {
        'le': '<=',
        'lt': '<',
        'ge': '>=',
        'gt': '>',
        'eq': '=',
        'ne': '!=',
}

class GlksaTypeException(Exception):
	def __init__(self, doctype):
		Exception.__init__(self, "wrong DOCTYPE: %s" % doctype)

class GlksaFormatException(Exception):
	pass

class GlksaArgumentException(Exception):
	pass

class GlksaException(Exception):
    pass

def makeConfig(c):
    rValue = (c.getAttribute("value"), getText(c, format="strip"))
    return rValue

def makeVersion(c):
    rValue = (opMapping[c.getAttribute("range")], getText(c, format="strip"))
    return rValue

def getKernelVersion():
    try:
        f = gzip.open('/proc/config.gz')
    except IOError as e:
        raise GlksaException("/proc/config.gz is required for glksa-check to operate. Please enable /proc/config.gz in your kernel.")
    kernel_config = str(f.read())
    f.close()
    version = kv.findall(kernel_config)
    if not version:
        raise GlksaException("Malformed /proc/config.gz: kernel version not specified")
    version = version[0]
    return version

def getKernelOptions():
    try:
        f = gzip.open('/proc/config.gz')
    except IOError as e:
        raise GlksaException("/proc/config.gz is required for glksa-check to operate. Please enable /proc/config.gz in your kernel.")
    kernel_config = str(f.read())
    f.close()
    config = kc.findall(kernel_config)
    return config

    
class Glksa:
    def __init__(self, myid, myconfig):
        self.nr = myid
        self.config = myconfig
        self.read()

    def read(self):
        path = self.config["GLSA_DIR"] + self.config["GLSA_PREFIX"] + str(self.nr) + self.config["GLSA_SUFFIX"]
        self.parse(open(path))

    def parse(self, text):
        name = "sys-kernel/gentoo-sources"
        self.DOM = xml.dom.minidom.parse(text)
        self.glksaid = self.DOM.getElementsByTagName("glksa")[0].getAttribute("id")
        myroot = self.DOM.getElementsByTagName("glksa")[0]
        self.title = getText(myroot.getElementsByTagName("title")[0], format="strip")
        self.synopsis = getText(myroot.getElementsByTagName("synopsis")[0], format="strip")
        self.announced = format_date(getText(myroot.getElementsByTagName("announced")[0], format="strip"))
        self.glsatype = myroot.getElementsByTagName("product")[0].getAttribute("type")
        self.product = getText(myroot.getElementsByTagName("product")[0], format="strip")
        self.affected = myroot.getElementsByTagName("affected")[0]
        self.vul_vers = [makeVersion(v) for v in self.affected.getElementsByTagName("vulnerable")]
        self.unaff_vers = [makeVersion(v) for v in self.affected.getElementsByTagName("unaffected")]
        self.vul_configs = [makeConfig(v) for v in self.affected.getElementsByTagName("config")]
        

    def isVulnerable(self):
        rValue = True
        
        v = getKernelVersion()
        c = getKernelOptions()

        for vul in self.vul_vers:
            value = vul[0]
            version = vul[1]
            match = False
            if (value == '<' or value == '<=') and vercmp(version, v) == 1: match = True
            if (value == '=' or value == '<=' or value == '>=') and vercmp(version, v) == 0:    match = True
            if (value == '>' or value == '>=') and vercmp(version, v) == -1:    match = True
            if (value == '!=') and vercmp(version, v) != 0: match = True
            if not match:
                rValue = False

        for conf in self.vul_configs:
            match = False
            exists = False
            for conf_current in c:
                if re.match(conf[0], conf_current[1]):
                    exists = True
                    if re.match(conf[1], conf_current[0]): match = True
            if not(match) and not(exists and conf[0] == ""):
                rValue = False

        return rValue

optionmap = [
        ["-l", "--list", "list all the GLKSAs you are affected by"],
        ["-h", "--help", "print help page"],
]

args = []
params = []
try:
    args, params = getopt(sys.argv[1:], ''.join([opt[0][1] for opt in optionmap]), [x[2:] for x in reduce(lambda x,y: x+y, [z[1:-1] for z in optionmap])])
    args = [a for a, b in args]

    if len(args) <= 0:
        sys.stderr.write("No option given\n")
        mode = "HELP"
    elif len(args) > 1:
        sys.stderr.write("One command per call\n")
        mode = "HELP"
    else:
        args = args[0]
        for m in optionmap:
            if args in [o for o in m[:-1]]:
                mode = m[1][2:]
except GetoptError as e:
    sys.stderr.write("unknown option given: ")
    sys.stderr.write(str(e)+"\n")
    mode = "HELP"


if mode == "HELP" or mode == "help":
    msg = "Syntax: glksa-check <option>\n\n"
    for m in optionmap:
        msg += m[0] + "\t" + m[1] + "   \t: " + m[-1] + "\n"
        for o in m[2:-1]:
            msg += "\t" + o + "\n"
    if mode == "help":
        sys.stdout.write(msg)
        sys.exit(0)
    else:
        sys.stderr.write("\n" + msg)
        sys.exit(1)


mysettings = {
    "GLSA_DIR": portage.settings["PORTDIR"]+"/metadata/glksa/",
    "GLSA_PREFIX": "glksa-",
    "GLSA_SUFFIX": ".xml"
}


if mode == "list":
    glksas = get_glsa_list(mysettings["GLSA_DIR"], mysettings)
    glksas = [Glksa(g, mysettings) for g in glksas]
    for glksa in glksas:
        status = "UNAFFECTED"
        if glksa.isVulnerable():
            status = "AFFECTED"
        sys.stdout.write("[%s] %s: %s\n" % (status, glksa.glksaid, glksa.title))

