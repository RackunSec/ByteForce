# ByteForce
Offline Digital Forensics Tool for Binary Files
This tool can be used for (offline) digital forensics and malware analysis as it shows all raw bytes of a file and also the ASCII representations. As you can see from the screenshots, I have used it on a few different file types, TXT, PNG, Compiled C code, and even a packet capture file. It has three columns, one to show the byte count on the far left. Then, in the middle the hexadecimal bytes of the file, and on the right the ASCII representations (if there are any) of the hexadecimal bytes.

_Screenshot: ByteForce reading a binary file_

<img src="https://weaknetlabs.com/images/bf-01.png"/>

For the colored output, you will need a 256-color capable terminal emulator. I am using Gnome-Terminal in the screenshots.
## Features
ByteForce has some features that were unexpectedly added. After reading a few sites about malware, including the MalwareByte's weblog, here http://blog.malwarebytes.org/intelligence/2013/03/obfuscation-malwares-best-friend I decided to implement a few of the ideas shared in the article into the code.
### HTTP Strings
ByteForce will search Binary files for case-insensitive, plain-text HTTP strings.
### XOR Brute Force attack (Case-Insensitive)
The XOR brute force attack will try every byte from 0x01 to 0x1f as a XOR key against the byte found in the file. If the result equals the ASCII value of an "H" or "h" I grab the next byte in the file, perform the XOR and look for a "T" ot "t". I continue until I find "[Hh][Tt]{2}[pP]" and if found, I print the bytes until I get a non printable character. The algorithm I wrote will trace steps back into the opened file's bytes accordingly if a non http ASCII value is found.
### Rotate 13 Check
This will perform a simple ROT13() function that I made on the byte before checking it's value for the "[Hh][tT]{2}[pP]" ASCII values that I searched for in the XOR segment above.
### XOR-ROT13 Attack
This will perform the brute-force XOR attack after performing the ROT13() function I made on the file's byte before checking it for the "[Hh][tT]{2}[pP]" ASCII values.
### PDF Documents
ByteForce has the ability to check the document for a valid PDF header and also to search for plain-text case-insensitive executable file names. This does not deflate/inflate data streams. This is a simple string check on the file.

_Screenshot: ByteForce showing a potentially dangerous PDF file_

<img src="https://weaknetlabs.com/images/bf-07.png"/>
## Screenshots
_Screenshot: ByteForce reading a binary file for plain-text HTTP strings, ROT13() HTTP strings and XOR->ROT13() strings_

<img src="https://weaknetlabs.com/images/bf-02.png"/>

_Screenshot: ByteForce reading a PNG file_

<img src="https://weaknetlabs.com/images/bf-03.png"/>

_Screenshot: ByteForce reading a 802.11 WiFi network PCAP file_

<img src="https://weaknetlabs.com/images/bf-04.png"/>
## Compiling
To compile ByteForce, simply type ```make``` at the command line. I used no special resources or libraries but a few of the default header files from GNU C.
_Screenshot: Compiling ByteForce is easy!_

<img src="https://weaknetlabs.com/images/bf-05.png"/>
## TODO
* Organize the PCAP file output using the RadioTap headers as delimiters
* Add Base64 decode attempt attack on possible strings
* ~~PE/MSDOS validation from Headers~~
* ~~Search PDFs for file header and executable code~~
* ~~Clean up output for "| head" streaming~~
* Search documents for hidden executable code

## References
* ROT13: https://en.wikipedia.org/wiki/ROT13 
* MalwareByte's Weblog: https://blog.malwarebytes.com/threat-analysis/2013/03/obfuscation-malwares-best-friend/
* XOR: https://en.wikipedia.org/wiki/Exclusive_or
* Gnome-Terminal: https://en.wikipedia.org/wiki/GNOME_Terminal
* Weakerthan Linux 7 BETA: http://www.weaknetlabs.com/2016/05/weakerthan-linux-7-beta-2-release.html
* ASCII Table: http://www.asciitable.com/
* PDF Headers: http://resources.infosecinstitute.com/pdf-file-format-basic-structure/
