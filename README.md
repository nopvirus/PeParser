# PeParser
PeParser is check static analysis on PE(Portable Executable) File


## Update
* 2018-05-01: Measure entropy value of each section
* 2018-04-30: Support x64
* 2018-04-26: first version


## Usage
<pre><code>
PeParser.py <-s or -p> -f <filename>

PeParser.py -s -f kernel32.dll  [PRINT Section Information]

[*] IMAGE_SECTION_HEADER Information
  Name     RVA    VirSize   RawSize    entropy
.text     0x10000  0x5ea06  0x5f000     6.55
.rdata    0x70000  0x26f2c  0x27000     5.86
.data     0xa0000    0xc34   0x1000     1.11
.rsrc     0xb0000    0x520   0x1000     1.31
.reloc    0xc0000   0x44c4   0x5000      6.3
</code></pre>

<pre><code>
PeParser.py -p -f malware.exe   [PRINT Default Information]

</code></pre>

