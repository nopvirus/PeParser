import sys
import struct
import ctypes
import math
import argparse

BYTE = ctypes.c_byte
WORD = ctypes.c_ushort
ULONG = ctypes.c_uint32
LONG = ctypes.c_int32
DOUBLE = ctypes.c_double

class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ('e_magic',WORD),
        ('e_cblp',WORD),
        ('e_cp',WORD),
        ('e_crlc',WORD),
        ('e_cparhdr',WORD),
        ('e_minalloc',WORD),
        ('e_maxalloc',WORD),
        ('e_ss',WORD),
        ('e_sp',WORD),
        ('e_csum',WORD),
        ('e_ip',WORD),
        ('e_cs',WORD),
        ('e_lfarlc',WORD),
        ('e_ovno',WORD),
        ('e_res',WORD*4),
        ('e_oemid',WORD),
        ('e_oeminfo',WORD),
        ('e_res2',WORD*10),
        ('e_lfanew',ULONG ),
    ]

class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ('Machine',WORD),
        ('NumberOfSections',WORD),
        ('TimeDateStamp',LONG),
        ('PointerToSymbolTable',LONG),
        ('NumberOfSymbols',LONG),
        ('SizeOfOptionalHeader',WORD),
        ('Characteristics',WORD),
    ]

class IMAGE_OPTIONAL_HEADER32(ctypes.Structure):
    _fields_ = [
        ('Magic',WORD),
        ('MajorLinkerVersion',BYTE),
        ('MinorLinkerVersion',BYTE),
        ('SizeOfCode',LONG),
        ('SizeOfInitializedData',LONG),
        ('SizeOfUninitializedData',LONG),
        ('AddressOfEntryPoint',LONG),
        ('BaseOfCode',LONG),
        ('BaseOfData',LONG),
        ('ImageBase',LONG),
        ('SectionAlignment',LONG),
        ('FileAlignment',LONG),
        ('MajorOperatingSystemVersion',WORD),
        ('MinorOperatingSystemVersion',WORD),
        ('MajorImageVersion',WORD),
        ('MinorImageVersion',WORD),
        ('MajorSubsystemVersion',WORD),
        ('MinorSubsystemVersion',WORD),
        ('Win32VersionValue',LONG),
        ('SizeOfImage',LONG),
        ('SizeOfHeaders',LONG),
        ('CheckSum',LONG),
        ('Subsystem',WORD),
        ('DllCharacteristics',WORD),
        ('SizeOfStackReserve',LONG),
        ('SizeOfStackCommit',LONG),
        ('SizeOfHeapReserve',LONG),
        ('SizeOfHeapCommit',LONG),
        ('LoaderFlags',LONG),
        ('NumberOfRvaAndSizes',LONG),
    ]


class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
    _fields_ = [
        ('Magic',WORD),
        ('MajorLinkerVersion',BYTE),
        ('MinorLinkerVersion',BYTE),
        ('SizeOfCode',LONG),
        ('SizeOfInitializedData',LONG),
        ('SizeOfUninitializedData',LONG),
        ('AddressOfEntryPoint',LONG),
        ('BaseOfCode',LONG),
        ('BaseOfData',LONG),
        ('ImageBase',DOUBLE),
        ('SectionAlignment',LONG),
        ('FileAlignment',LONG),
        ('MajorOperatingSystemVersion',WORD),
        ('MinorOperatingSystemVersion',WORD),
        ('MajorImageVersion',WORD),
        ('MinorImageVersion',WORD),
        ('MajorSubsystemVersion',WORD),
        ('MinorSubsystemVersion',WORD),
        ('Win32VersionValue',LONG),
        ('SizeOfImage',LONG),
        ('SizeOfHeaders',LONG),
        ('CheckSum',LONG),
        ('Subsystem',WORD),
        ('DllCharacteristics',WORD),
        ('SizeOfStackReserve',DOUBLE),
        ('SizeOfStackCommit',DOUBLE),
        ('SizeOfHeapReserve',DOUBLE),
        ('SizeOfHeapCommit',DOUBLE),
        ('LoaderFlags',LONG),
        ('NumberOfRvaAndSizes',LONG),
    ]


class IMAGE_SECTION_HEADER(ctypes.Structure):
    _fields_ = [
        ('Name',BYTE*8),
        ('VirtualSize',LONG),
        ('RVA',LONG),
        ('SizeofRawData',LONG),
        ('PointertoRawData',LONG),
        ('PointertoRelocations',LONG),
        ('PointertoLineNumbers',LONG),
        ('NumberofRelocations',WORD),
        ('NumberofLineNumbers',WORD),
        ('Characteristics',LONG),
    ]

class PeParser():
    DOS_HEADER = {}
    FILE_HEADER = {}
    OPTIONAL_HEADER = {}
    DATA_DIRECTORY = []
    SECTION_HEADER = []

    __DATA_DIRECTORY_Struct__ = {'VirtualAddress':0,'Size':0}
    __SECTION_HEADER_Struct__ = {
    'Name':"",
    'VirtualSize':0,
    'RVA':0,
    'SizeOfRawData':0,
    'PointerToRawData':0,
    'PointerToRelocations':0,
    'PointerToLinenumbers':0,
    'NumberOfRelocations':0,
    'NumberOfLinenumbers':0,
    'Characteristics':0
    }

    __dos_sig__ = 0x5a4d
    __nt_sig__ = 0x00004550

    __opt_x32__ = 0x010b
    __opt_x64__ = 0x020b

    filesize = 0
    fname = ""
    Is32Bit = False


    def __GetDword__(self, buff, off):
        return struct.unpack("<L", buff[off:off+4])[0]

    def __GetWord__(self, buff, off):
        return struct.unpack("<H", buff[off:off+2])[0]

    def __init__(self, name=None):
        if name is None:
            raise ValueError('Need to filename')

        try:
            self.__Parse__(name)
        except:
            return


    def __Convert__(self, _format, _data, _type):
        if _type == 1:
            for ElmtList in _format._fields_:
                Elmt = ElmtList[0]
                self.DOS_HEADER[Elmt] = _data.__getattribute__(Elmt)
        elif _type == 2:
            for ElmtList in _format._fields_:
                Elmt = ElmtList[0]
                self.FILE_HEADER[Elmt] = _data.__getattribute__(Elmt)
        elif _type == 3:
            for ElmtList in _format._fields_:
                Elmt = ElmtList[0]
                self.OPTIONAL_HEADER[Elmt] = _data.__getattribute__(Elmt)
        elif _type == 4:
            for ElmtList in _format._fields_:
                Elmt = ElmtList[0]
                self.OPTIONAL_HEADER[Elmt] = _data.__getattribute__(Elmt)

    def RvatoRaw(self, Rva):
        for _section in self.SECTION_HEADER:
            if _section['RVA'] <= Rva and Rva < (_section['RVA']+_section['VirtualSize']):
                Raw = (Rva - _section['RVA']) + _section['PointerToRawData']
                return Raw

        return None


    def __Parse__(self, name = None):
        if name == None:
            print "Need to filename"
            return None

        f = open(name,'rb')
        buff= f.read()
        f.close()

        self.filesize = len(buff)

        _DosHdr_size = ctypes.sizeof(IMAGE_DOS_HEADER)
        _FileHdr_size = ctypes.sizeof(IMAGE_FILE_HEADER)
        _Opt32Hdr_size = ctypes.sizeof(IMAGE_OPTIONAL_HEADER32)
        _Opt64Hdr_size = ctypes.sizeof(IMAGE_OPTIONAL_HEADER64)

        _Dos_hdr = IMAGE_DOS_HEADER()
        _File_hdr = IMAGE_FILE_HEADER()
        _Opt32_hdr = IMAGE_OPTIONAL_HEADER32()
        _Opt64_hdr = IMAGE_OPTIONAL_HEADER64()

        #Read Dos Header
        ctypes.memmove(ctypes.addressof(_Dos_hdr),buff, _DosHdr_size)
        self.__Convert__(IMAGE_DOS_HEADER(), _Dos_hdr, 1)

        if self.DOS_HEADER['e_magic'] != self.__dos_sig__:
            print 'dos signature not a match'
            return None


        off = self.DOS_HEADER['e_lfanew']

        if off >= self.filesize :
            print 'malformed PE Structure'
            return None

        #temp = struct.unpack( '<L',buff[off:off+4] )[0]
        temp = self.__GetDword__(buff,off)
        if temp != self.__nt_sig__:
            print 'PE signature not a match'
            return None

        off += 4
        ctypes.memmove(ctypes.addressof(_File_hdr), buff[off:], _FileHdr_size)
        self.__Convert__(IMAGE_FILE_HEADER(), _File_hdr, 2)

        #offset to Optional header
        off += _FileHdr_size

        magic = self.__GetWord__(buff, off)
        if magic == self.__opt_x32__:
            self.Is32Bit = True
        elif magic == self.__opt_x64__:
            self.Is32Bit = False


        if self.Is32Bit == True:
            ctypes.memmove(ctypes.addressof(_Opt32_hdr), buff[off:], _Opt32Hdr_size)
            self.__Convert__(IMAGE_OPTIONAL_HEADER32(), _Opt32_hdr, 3)
            Imsi = off + _Opt32Hdr_size
        else:
            ctypes.memmove(ctypes.addressof(_Opt64_hdr), buff[off:], _Opt64Hdr_size)
            self.__Convert__(IMAGE_OPTIONAL_HEADER64(), _Opt64_hdr, 4)
            Imsi = off + _Opt64Hdr_size


        for i in xrange(0, self.OPTIONAL_HEADER['NumberOfRvaAndSizes']):
            self.__DATA_DIRECTORY_Struct__['VirtualAddress'] = self.__GetDword__(buff, Imsi)
            self.__DATA_DIRECTORY_Struct__['Size'] = self.__GetDword__(buff, Imsi+4)
            self.DATA_DIRECTORY.append(self.__DATA_DIRECTORY_Struct__.copy())  #do not ref copy
            Imsi += 8

        off = off + self.FILE_HEADER['SizeOfOptionalHeader']

        for i in xrange(0, self.FILE_HEADER['NumberOfSections']):
            self.__SECTION_HEADER_Struct__['Name'] = buff[off:off+8]
            self.__SECTION_HEADER_Struct__['VirtualSize'] = self.__GetDword__(buff, off+8)
            self.__SECTION_HEADER_Struct__['RVA'] = self.__GetDword__(buff, off+12)
            self.__SECTION_HEADER_Struct__['SizeOfRawData'] = self.__GetDword__(buff, off+16)
            self.__SECTION_HEADER_Struct__['PointerToRawData'] = self.__GetDword__(buff, off+20)
            self.__SECTION_HEADER_Struct__['PointerToRelocations'] = self.__GetDword__(buff, off+24)
            self.__SECTION_HEADER_Struct__['PointerToLinenumbers'] = self.__GetDword__(buff, off+28)
            self.__SECTION_HEADER_Struct__['NumberOfRelocations'] = self.__GetWord__(buff, off+32)
            self.__SECTION_HEADER_Struct__['NumberOfLinenumbers'] = self.__GetWord__(buff, off+34)
            self.__SECTION_HEADER_Struct__['Characteristics'] = self.__GetDword__(buff, off+36)
            self.SECTION_HEADER.append(self.__SECTION_HEADER_Struct__.copy())
            off += 40

        return

    def GetEntropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x)))/len(data)
            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)
        return round(entropy, 2)    #roundup 6.135 -> 6.14

def helpcmd():
    print "CMD> %s filename" % (sys.argv[0])

def PrintPeInfo(filename):
    Info = PeParser(name = filename)

    print '[*] IMAGE_DOS_HEADER:'
    print '\te_lfanew:%s' % (Info.DOS_HEADER['e_lfanew'])

    print '\n[*] IMAGE_FILE_HEADER:'
    for Elmt in Info.FILE_HEADER:
        print '\t%s : %x'%(Elmt, Info.FILE_HEADER[Elmt])

    print '\n[*] IMAGE_OPTIONAL_HEADER32:'
    for Elmt in Info.OPTIONAL_HEADER:
        print '\t%s : %x'%(Elmt, Info.OPTIONAL_HEADER[Elmt])


    print '\n[*] IMAGE_SECTION_HEADER:'
    for i in xrange(0,Info.FILE_HEADER['NumberOfSections']):
        print ' -> Section %d' %(i)
        for Section in Info.SECTION_HEADER[i]:
            if Section == "Name":
                print '%s : %s'%(Section, Info.SECTION_HEADER[i][Section])
            else:
                print '%s : %x'%(Section, Info.SECTION_HEADER[i][Section])
        print '\n'

def PrintSectionInfo(filename):
    Info = PeParser(name = filename)

    f = open(filename, 'rb')
    buff = f.read();
    f.close()

    print '[*] IMAGE_SECTION_HEADER Information'
    print '{:^8} {:^8} {:^8} {:^10} {:^10}'.format("Name", "RVA", "VirSize", "RawSize", "entropy")
    for i in xrange(0,Info.FILE_HEADER['NumberOfSections']):
        Offset = Info.SECTION_HEADER[i]['PointerToRawData']
        Size = Info.SECTION_HEADER[i]['SizeOfRawData']
        SectionData = buff[Offset : Offset + Size]
        Entropy =  Info.GetEntropy(SectionData)
        #print '%s %x %x %x %x' % (Info.SECTION_HEADER[i]['Name'] ,Info.SECTION_HEADER[i]['RVA'] ,Info.SECTION_HEADER[i]['VirtualSize']. Info.SECTION_HEADER[i]['SizeOfRawData'], Entropy)
        #print '%s {:>8%x} %x %x %f' % (Info.SECTION_HEADER[i]['Name'], Info.SECTION_HEADER[i]['RVA'], Info.SECTION_HEADER[i]['VirtualSize'], Info.SECTION_HEADER[i]['SizeOfRawData'] ,Entropy)
        print '{:>8} {:>8} {:>8} {:>8} {:>8}'.format(Info.SECTION_HEADER[i]['Name'], hex(Info.SECTION_HEADER[i]['RVA']), hex(Info.SECTION_HEADER[i]['VirtualSize']), hex(Info.SECTION_HEADER[i]['SizeOfRawData']) ,Entropy)


if __name__ == "__main__":
    parse = argparse.ArgumentParser()
    parse.add_argument("-s",  help="Print Section info", action="store_true")
    parse.add_argument("-p",  help="Print Defalt PE info", action="store_true")
    parse.add_argument("-f", type=str, metavar="filename", help="target filename", required = True)
    args = parse.parse_args()
    if args.s:
        PrintSectionInfo(args.f)
    elif args.p:
        PrintPeInfo(args.f)
    else:
        print 'Argument Error'
