#!/usr/bin/env python

import argparse
import hashlib
import pathlib
import sys
import xml.etree.ElementTree as ET
import xml.sax
import zipfile
import zlib


class BadRPKError(Exception):
    pass


class BadDataError(Exception):
    pass


def check_data(name, data, size, crc, sha1):
    if len(data) != size:
        raise BadDataError("%s has wrong length %d != %d" %
                           (name, len(data), size))
    elif hashlib.sha1(data).digest().hex() != sha1:
        raise BadDataError("%s has wrong sha1 %s != %s" % (
            name, hashlib.sha1(data).digest().hex(), sha1))
    elif "%08x" % zlib.crc32(data) != crc:
        raise BadDataError("%s has wrong crc32 %s != %s" % (
            name, "%08x" % zlib.crc32(data), crc))


class DataArea:
    def __init__(self, size):
        if size < 0 or size > 0x10000:
            raise ValueError("Invalid dataarea size %d" % (size,))
        self.size = size
        self.roms = []
        self.data = None

    def add_rom(self, name, size, crc, sha1, offset):
        if offset < 0 or offset + size > self.size:
            raise ValueError("Rom %s is outside range [0:0x%04x]" %
                             (name, size))
        for name2, size2, _, _, offset2 in self.roms:
            if (offset <= offset2 and offset+size > offset2) or (
                    offset >= offset2 and offset < offset2+size2):
                raise ValueError("Overlapping roms %s and %s" %
                                 (name, name2))
        self.roms.append((name, size, crc, sha1, offset))

    def load_from_zip(self, zip):
        if self.data is not None:
            raise ValueError("DataArea loaded twice")
        self.data = bytearray(self.size)
        for name, size, crc, sha1, offset in self.roms:
            data = zip.read(name)
            check_data(name, data, size, crc, sha1)
            self.data[offset:offset+size] = data


class GromDataArea(DataArea):
    def __init__(self, size):
        if (size % 0x2000) not in (0, 0x1800) or size > 0xa000:
            raise ValueError("Invalid grom dataarea size %d" % (size,))
        DataArea.__init__(self, size)

    def add_rom(self, name, size, crc, sha1, offset):
        if size != 0x1800 and (size % 0x2000) != 0:
            raise ValueError("Invalid GROM size %d" % (size,))
        if (offset % 0x2000) != 0:
            raise ValueError("Invalid GROM offset %d" % (offset,))
        DataArea.add_rom(self, name, size, crc, sha1, offset)

    def load_from_zip(self, zip):
        DataArea.load_from_zip(self, zip)
        for name, size, crc, sha1, offset in self.roms:
            for o in range(offset, offset+size, 0x2000):
                if o+0x1800 < len(self.data):
                    self.update_garbage(name, o, offset+size-o,
                                        0x800 if o+0x2000 <= len(self.data)
                                        else self.data-(o+0x1800))

    def update_garbage(self, name, offs, datasize, garbagesize):
        if datasize < 0x1800:
            raise RuntimeError("Too little data to generate garbage!?")
        fixed = False
        for o in range(0, garbagesize):
            garbage = self.data[offs+0x800+o] | self.data[offs+0x1000+o]
            if self.data[offs+0x1800+o] != garbage:
                if 0x1800+o < datasize:
                    fixed = True
                self.data[offs+0x1800+o] = garbage
        if fixed:
            print("WARNING: %s has incorrect garbage, updated" % (name,),
                  file=sys.stderr)


class Cartridge:
    def __init__(self, name):
        self.name = name
        self.metadata = {}
        self.pcb = None
        self.dataareas = {}

    def set_metadata(self, name, value):
        self.metadata[name] = value

    def set_pcb(self, name):
        self.pcb = name

    def get_dataarea(self, name, size=None):
        if name.endswith("_socket"):
            name = name[:-7]
        if name not in ('rom', 'rom2', 'grom', 'ram', 'nvram'):
            raise ValueError("Unknown dataarea %s" % (name,))
        if name not in self.dataareas:
            if size is None:
                return None
            elif name == "grom" and self.pcb != "gromemu":
                self.dataareas[name] = GromDataArea(size)
            else:
                self.dataareas[name] = DataArea(size)
        elif size is not None and self.dataareas[name].size != size:
            raise ValueError("Redeclared dataarea %s with different size" %
                             (name,))
        return self.dataareas[name]

    def load_from_zip(self, zip):
        for da in self.dataareas.values():
            da.load_from_zip(zip)


class CartXmlContentHandler(xml.sax.handler.ContentHandler):

    def startDocument(self):
        self.softwarelist = {}
        self.software = None
        self.dataarea = None
        self.content = None

    def startElement(self, name, attrs):
        self.content = ""
        if name == "software":
            self.software = Cartridge(attrs["name"])
        elif self.software is not None:
            if name in ('description', 'year', 'publisher'):
                pass
            elif name == "info":
                self.software.set_metadata(attrs["name"], attrs["value"])
            elif name == "part":
                if (attrs["name"] != "cart"
                        or attrs["interface"] != "ti99_cart"):
                    raise SyntaxError("Bad part element")
            elif name == "feature":
                if attrs["name"] != "pcb":
                    raise SyntaxError("Unknow feature %s" % (attrs["name"],))
                else:
                    self.software.set_pcb(attrs["value"])
            elif name == "dataarea":
                name = attrs["name"]
                if name.startswith('rom2'):
                    raise ValueError("Unknown dataarea %s" % (name,))
                self.dataarea = self.software.get_dataarea(
                    name, int(attrs["size"], 0))
            elif name == "rom":
                if self.dataarea is None:
                    raise SyntaxError("rom outside dataarea")
                else:
                    self.dataarea.add_rom(attrs["name"], int(attrs["size"], 0),
                                          attrs["crc"], attrs["sha1"],
                                          int(attrs["offset"], 0))
            else:
                raise SyntaxError("Unknown element %s" % (name,))

    def endElement(self, name):
        if self.software is not None:
            if name == "software":
                if self.software.pcb is None:
                    raise SyntaxError("Cartridge %s is missing a pcb type" %
                                      (self.software.name,))
                self.softwarelist[self.software.name] = self.software
                self.software = None
                self.dataarea = None
            elif name in ('description', 'year', 'publisher'):
                self.software.set_metadata(name, self.content)
            elif name == "dataarea":
                self.dataarea = None
        self.content = None

    def characters(self, content):
        if self.content is not None:
            self.content += content


class LayoutXmlContentHandler(xml.sax.handler.ContentHandler):

    def __init__(self, cartridge, rpk):
        xml.sax.handler.ContentHandler.__init__(self)
        self.cartridge = cartridge
        self.rpk = rpk
        self.resources = None

    def startElement(self, name, attrs):
        if name == 'romset':
            if "listname" in attrs:
                self.cartridge.name = attrs["listname"]
        elif name == 'resources':
            self.resources = {}
        elif name == 'rom':
            filename = attrs["file"]
            data = None
            try:
                data = self.rpk.read(filename)
            except KeyError:
                for fn in self.rpk.namelist():
                    if fn.lower() == filename.lower():
                        print("WARNING: case mismatch - layout.xml has %s "
                              "but actual zip entry is %s" % (filename, fn),
                              file=sys.stderr)
                        data = self.rpk.read(fn)
                        break
                if data is None:
                    raise BadRPKError("%s is missing in zip" % (filename,))
            self.resources[attrs["id"]] = (filename, data)
        elif name == 'ram':
            filename = attrs["file"] if "file" in attrs else None
            self.resources[attrs["id"]] = (
                filename, bytes(int(attrs["length"], 0)))
        elif name == 'configuration':
            pass
        elif name == 'pcb':
            self.cartridge.set_pcb(attrs["type"])
        elif name == 'socket':
            filename, data = self.resources[attrs["uses"]]
            if attrs["id"] == "grom_socket" and len(data) % 0x2000 != 0:
                data += bytes(0x2000-(len(data) % 0x2000))
            da = self.cartridge.get_dataarea(attrs["id"], len(data))
            if len(da.roms):
                raise BadRPKError("socket %s defined twice" % (attrs["id"],))
            da.data = data
            da.add_rom(filename, len(data), "%08x" % zlib.crc32(data),
                       hashlib.sha1(data).digest().hex(), 0)
        else:
            raise SyntaxError("Unknown element %s" % (name,))


class MetaInfXmlContentHandler(xml.sax.handler.ContentHandler):

    def startDocument(self):
        self.metadata = {}
        self.content = None

    def startElement(self, name, attrs):
        self.content = ""

    def endElement(self, name):
        if name in ('name', 'year', 'dist', 'number'):
            self.metadata[name] = self.content
        self.content = None

    def characters(self, content):
        if self.content is not None:
            self.content += content


def write_rpk(rpk, cart):
    base = (cart.name if "serial" not in cart.metadata else
            ''.join(cart.metadata["serial"].lower().split()))
    areac = cart.get_dataarea('rom')
    areag = cart.get_dataarea('grom')
    datac = None
    datad = None
    if areac is not None:
        if cart.pcb == "paged12k" and (len(areac.roms) != 2 or
                                       areac.roms[0][1] != 0x1000 or
                                       areac.roms[1][1] != 0x2000):
            raise ValueError('Invalid paged12k cartridge')
        elif (len(areac.roms) == 2 and
                cart.pcb in ("paged7", "paged12k", "paged16k", "gromemu")):
            pass
        elif len(areac.roms) != 1:
            raise ValueError('Invalid number of roms in dataarea "rom"')
        offs = 0
        for _, size, _, _, offset in areac.roms:
            if size > (0x4000 if cart.pcb == "mbx" else 0x2000):
                raise ValueError("rom too large")
            if offset != offs:
                raise ValueError("wrong rom offset")
            if cart.pcb == "paged12k":
                data = areac.data[0:0x1000]
                if offs == 0:
                    data += areac.data[0x2000:0x3000]
                else:
                    data += areac.data[0x3000:0x4000]
            else:
                data = areac.data[offset:offset+size]
            if offs == 0:
                datac = data
            else:
                datad = data
            rpk.writestr(base+('c.bin' if offset == 0 else 'd.bin'), data)
            offs += 0x2000
    if areag is not None:
        rpk.writestr(base+'g.bin', areag.data)
    pcbtype = "paged" if cart.pcb.startswith("paged") else cart.pcb
    romset = ET.Element('romset', {'version': "1.0", 'listname': cart.name})
    resources = ET.SubElement(romset, 'resources')
    configuration = ET.SubElement(romset, 'configuration')
    pcb = ET.SubElement(configuration, 'pcb', type=pcbtype)
    if areag is not None:
        ET.SubElement(resources, 'rom', id="gromimage", file=base+'g.bin')
        ET.SubElement(pcb, 'socket', id="grom_socket", uses="gromimage")
    if areac is not None:
        ET.SubElement(resources, 'rom', id="romimage", file=base+'c.bin')
        ET.SubElement(pcb, 'socket', id="rom_socket", uses="romimage")
        if len(areac.roms) == 2:
            ET.SubElement(resources, 'rom', id="rom2image", file=base+'d.bin')
            ET.SubElement(pcb, 'socket', id="rom2_socket", uses="rom2image")
    ET.indent(romset, '   ')
    layout = ET.tostring(romset, encoding='utf-8', xml_declaration=True)+b'\n'
    rpk.writestr('layout.xml', layout)
    meta_inf = ET.Element('meta-inf')
    for key, elt in [('description', 'name'), ('year', 'year'),
                     ('publisher', 'dist'), ('serial', 'number')]:
        if key in cart.metadata:
            ET.SubElement(meta_inf, elt).text = cart.metadata[key]
    if 'version' in cart.metadata:
        ET.SubElement(meta_inf, 'status', version=cart.metadata['version'])
    ET.indent(meta_inf, '  ')
    minfo = ET.tostring(meta_inf, encoding='utf-8', xml_declaration=True)+b'\n'
    rpk.writestr('meta-inf.xml', minfo)
    software = ET.Element('software', name=cart.name)
    for key in ('description', 'year', 'publisher'):
        if key in cart.metadata:
            ET.SubElement(software, key).text = cart.metadata[key]
    for key in sorted(cart.metadata.keys()):
        if key not in ('description', 'year', 'publisher'):
            ET.SubElement(software, 'info', name=key, value=cart.metadata[key])
    part = ET.SubElement(software, 'part', name="cart", interface="ti99_cart")
    ET.SubElement(part, 'feature', name="pcb", value=pcbtype)
    if areag is not None:
        ET.SubElement(ET.SubElement(part, 'dataarea', name="grom_socket",
                                    size="0x%04x" % (len(areag.data),)), 'rom',
                      name=base+'g.bin', size="0x%04x" % (len(areag.data),),
                      crc="%08x" % (zlib.crc32(areag.data),),
                      sha1=hashlib.sha1(areag.data).digest().hex(),
                      offset="0x0000")
    if datac is not None:
        ET.SubElement(ET.SubElement(part, 'dataarea', name="rom_socket",
                                    size="0x%04x" % (len(datac),)),
                      'rom', name=base+'c.bin', size="0x%04x" % (len(datac),),
                      crc="%08x" % (zlib.crc32(datac),),
                      sha1=hashlib.sha1(datac).digest().hex(),
                      offset="0x0000")
    if datad is not None:
        ET.SubElement(ET.SubElement(part, 'dataarea', name="rom2_socket",
                                    size="0x%04x" % (len(datad),)),
                      'rom', name=base+'d.bin', size="0x%04x" % (len(datad),),
                      crc="%08x" % (zlib.crc32(datad),),
                      sha1=hashlib.sha1(datad).digest().hex(),
                      offset="0x0000")
    ET.indent(software, '\t')
    sw = ET.Element(None)
    sw.insert(0, software)
    if 'description' in cart.metadata:
        comment = ET.Comment(" Softlist entry for %s " % (
            cart.metadata["description"],))
        comment.tail = "\n"
        sw.insert(0, comment)
    softlist = ET.tostring(sw, encoding='utf-8', xml_declaration=True)+b'\n'
    rpk.writestr('softlist.xml', softlist)


def validate_rpk(rpk, sw):
    pcb = sw.pcb
    if pcb.startswith('paged'):
        pcb = 'paged'
    if rpk.pcb != pcb:
        raise BadRPKError("pcb type is %s, should be %s" % (rpk.pcb, pcb))
    areac = rpk.get_dataarea('rom')
    aread = rpk.get_dataarea('rom2')
    areag = rpk.get_dataarea('grom')
    if sw.pcb == 'paged12k':
        if (areac is None or aread is None or
            areac.size != 0x2000 or aread.size != 0x2000 or
                areac.data[:0x1000] != aread.data[:0x1000]):
            raise BadRPKError("Bad ROM layout for pcb type paged12k")
        aread.data = areac.data[0x1000:0x2000] + aread.data[0x1000:0x2000]
    if pcb == 'paged':
        if areac is None or aread is None or areac.size != 0x2000:
            raise BadRPKError("Bad ROM layout for paged pcb")
        areac.size += aread.size
        areac.data += aread.data
        areac.roms.extend([(name, size, crc, sha1, offset+0x2000) for
                           (name, size, crc, sha1, offset) in aread.roms])
        aread = None
    if aread is not None:
        raise BadRPKError("bad use of rom2")
    for area, areaname in [(areac, 'rom'), (areag, 'grom')]:
        swarea = sw.get_dataarea(areaname)
        if swarea is not None:
            if area is None:
                raise BadRPKError("missing '%s' socket", (areaname,))
            for name, size, crc, sha1, offset in swarea.roms:
                if offset + size > len(area.data):
                    raise BadRPKError("socket '%s' does not have enough data"
                                      % (areaname,))
                check_data("%s @ 0x%04x" % (areaname, offset),
                           area.data[offset:offset+size], size, crc, sha1)


def main():
    parser = argparse.ArgumentParser("zip2rpk",
                                     description="Use ti99_cart.xml to "
                                     "create or validate RPK files")
    parser.add_argument('xml', help="Full path to ti99_cart.xml",
                        metavar='ti99_cart.xml', type=argparse.FileType('rb'))
    parser.add_argument('zip', help="zip file to load", nargs='?',
                        type=argparse.FileType('rb'))
    parser.add_argument('rpk', help="rpk file to create", nargs='?', type=str)
    parser.add_argument('--name', '-n', help="name in softwarelist",
                        metavar="list_name", type=str)
    parser.add_argument('--check', '-c', help="rpk file to check",
                        metavar="check_rpk", type=argparse.FileType('rb'))

    args = parser.parse_args()
    content_handler = CartXmlContentHandler()
    xml.sax.parse(args.xml, content_handler)
    softwarelist = content_handler.softwarelist
    cartridge = None
    cartname = args.name
    if args.zip is not None:
        if cartname is None:
            cartname = pathlib.Path(args.zip.name).stem
        if cartname not in softwarelist:
            raise KeyError("Unknown cartridge %s" % (cartname,))
        cartridge = softwarelist[cartname]
        with zipfile.ZipFile(args.zip) as zip:
            cartridge.load_from_zip(zip)
        print("%s loaded ok from %s" % (cartname, args.zip.name))
    if args.rpk is not None:
        if cartridge is None:
            raise RuntimeError("No cartridge loaded from zip")
        with zipfile.ZipFile(args.rpk, 'x', compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9) as rpk:
            write_rpk(rpk, cartridge)
            print("%s written ok to %s" % (cartridge.name, args.rpk))
    if args.check is not None:
        try:
            rpk_cartridge = Cartridge(None)
            with zipfile.ZipFile(args.check) as rpk:
                content_handler = LayoutXmlContentHandler(rpk_cartridge, rpk)
                with rpk.open('layout.xml') as layout:
                    xml.sax.parse(layout, content_handler)
                if cartname is None:
                    if rpk_cartridge.name is not None:
                        cartname = rpk_cartridge.name
                        print("Using cartname %s from rpk" % (cartname,))
                    else:
                        print("Trying to guess cartname from meta-inf.xml...")
                        content_handler = MetaInfXmlContentHandler()
                        with rpk.open('meta-inf.xml') as meta_inf:
                            xml.sax.parse(meta_inf, content_handler)
                        if 'number' in content_handler.metadata:
                            serial = content_handler.metadata['number']
                            matches = [sw for sw in softwarelist.values() if
                                       'serial' in sw.metadata and
                                       serial == sw.metadata['serial']]
                            if len(matches) == 1:
                                cartname = matches[0].name
                                print("Using cartname %s based on serial %s" %
                                      (cartname, serial))
                        if cartname is None:
                            raise RuntimeError(
                                "Unable to guess cartname, please use -n")
            if cartridge is None:
                if cartname in softwarelist:
                    cartridge = softwarelist[cartname]
                else:
                    raise KeyError("Unknown cartridge %s, please use -n" %
                                   (cartname,))
            validate_rpk(rpk_cartridge, cartridge)
        except (BadRPKError, BadDataError) as e:
            sys.exit("Bad RPK: %s" % (e,))
        print("rpk %s is valid for %s" % (args.check.name, cartname))


if __name__ == '__main__':
    main()
