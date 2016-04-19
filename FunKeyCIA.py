# FunKeyCIA

import sys
import os
import re
import binascii
from struct import unpack, pack
import urllib2
import argparse
import string
import hashlib
import datetime
from collections import namedtuple
from collections import Counter

if not sys.version_info[:2] == (2, 7):
    print '*****\n!!!!!Warning - Only tested with Python 2.7!!!!!\n*****\n'

windoze = '9c4f88f706dedde3bc0ebb66e34963e5'
magic = binascii.a2b_hex('00010004919ebe464ad0f552cd1b72e7884910cf55a9f02e50789641d896683dc005bd0aea87079d8ac284c675065f74c8bf37c88044409502a022980bb8ad48383f6d28a79de39626ccb2b22a0f19e41032f094b39ff0133146dec8f6c1a9d55cd28d9e1c47b3d11f4f5426c2c780135a2775d3ca679bc7e834f0e0fb58e68860a71330fc95791793c8fba935a7a6908f229dee2a0ca6b9b23b12d495a6fe19d0d72648216878605a66538dbf376899905d3445fc5c727a0e13e0e2c8971c9cfa6c60678875732a4e75523d2f562f12aabd1573bf06c94054aefa81a71417af9a4a066d0ffc5ad64bab28b1ff60661f4437d49e1e0d9412eb4bcacf4cfd6a3408847982000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526f6f742d43413030303030303033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000158533030303030303063000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000137a0894ad505bb6c67e2e5bdd6a3bec43d910c772e9cc290da58588b77dcc11680bb3e29f4eabbb26e98c2601985c041bb14378e689181aad770568e928a2b98167ee3e10d072beef1fa22fa2aa3e13f11e1836a92a4281ef70aaf4e462998221c6fbb9bdd017e6ac590494e9cea9859ceb2d2a4c1766f2c33912c58f14a803e36fccdcccdc13fd7ae77c7a78d997e6acc35557e0d3e9eb64b43c92f4c50d67a602deb391b06661cd32880bd64912af1cbcb7162a06f02565d3b0ece4fcecddae8a4934db8ee67f3017986221155d131c6c3f09ab1945c206ac70c942b36f49a1183bcd78b6e4b47c6c5cac0f8d62f897c6953dd12f28b70c5b7df751819a9834652625000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010003704138efbbbda16a987dd901326d1c9459484c88a2861b91a312587ae70ef6237ec50e1032dc39dde89a96a8e859d76a98a6e7e36a0cfe352ca893058234ff833fcb3b03811e9f0dc0d9a52f8045b4b2f9411b67a51c44b5ef8ce77bd6d56ba75734a1856de6d4bed6d3a242c7c8791b3422375e5c779abf072f7695efa0f75bcb83789fc30e3fe4cc8392207840638949c7f688565f649b74d63d8d58ffadda571e9554426b1318fc468983d4c8a5628b06b6fc5d507c13e7a18ac1511eb6d62ea5448f83501447a9afb3ecc2903c9dd52f922ac9acdbef58c6021848d96e208732d3d1d9d9ea440d91621c7a99db8843c59c1f2e2c7d9b577d512c166d6f7e1aad4a774a37447e78fe2021e14a95d112a068ada019f463c7a55685aabb6888b9246483d18b9c806f474918331782344a4b8531334b26303263d9d2eb4f4bb99602b352f6ae4046c69a5e7e8e4a18ef9bc0a2ded61310417012fd824cc116cfb7c4c1f7ec7177a17446cbde96f3edd88fcd052f0b888a45fdaf2b631354f40d16e5fa9c2c4eda98e798d15e6046dc5363f3096b2c607a9d8dd55b1502a6ac7d3cc8d8c575998e7d796910c804c495235057e91ecd2637c9c1845151ac6b9a0490ae3ec6f47740a0db0ba36d075956cee7354ea3e9a4f2720b26550c7d394324bc0cb7e9317d8a8661f42191ff10b08256ce3fd25b745e5194906b4d61cb4c2e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526f6f7400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001434130303030303030330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007be8ef6cb279c9e2eee121c6eaf44ff639f88f078b4b77ed9f9560b0358281b50e55ab721115a177703c7a30fe3ae9ef1c60bc1d974676b23a68cc04b198525bc968f11de2db50e4d9e7f071e562dae2092233e9d363f61dd7c19ff3a4a91e8f6553d471dd7b84b9f1b8ce7335f0f5540563a1eab83963e09be901011f99546361287020e9cc0dab487f140d6626a1836d27111f2068de4772149151cf69c61ba60ef9d949a0f71f5499f2d39ad28c7005348293c431ffbd33f6bca60dc7195ea2bcc56d200baf6d06d09c41db8de9c720154ca4832b69c08c69cd3b073a0063602f462d338061a5ea6c915cd5623579c3eb64ce44ef586d14baaa8834019b3eebeed3790001000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
tiktem = binascii.a2b_hex('00010004d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0d15ea5e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526f6f742d434130303030303030332d585330303030303030630000000000000000000000000000000000000000000000000000000000000000000000000000feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface010000cccccccccccccccccccccccccccccccc00000000000000000000000000aaaaaaaaaaaaaaaa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010014000000ac000000140001001400000000000000280000000100000084000000840003000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')

execname = './make_cdn_cia'
if hashlib.md5(sys.platform).hexdigest() == windoze:
    execname = 'make_cdn_cia.exe'

##########From https://stackoverflow.com/questions/5783517/downloading-progress-bar-urllib2-python
def chunk_report(bytes_so_far, chunk_size, total_size):
    percent = float(bytes_so_far) / total_size
    percent = round(percent*100, 2)
    sys.stdout.write("Downloaded %d of %d bytes (%0.2f%%)\r" % (bytes_so_far, total_size, percent))
    if bytes_so_far >= total_size:
        sys.stdout.write('\n')

def chunk_read(response, outfname, chunk_size=2*1024*1024, report_hook=None):
    fh = open(outfname,'wb')
    total_size = response.info().getheader('Content-Length').strip()
    total_size = int(total_size)
    bytes_so_far = 0
    data = []
    while 1:
        if report_hook:
            report_hook(bytes_so_far, chunk_size, total_size)
        chunk = response.read(chunk_size)
        bytes_so_far += len(chunk)
        if not chunk:
            break
        fh.write(chunk)
    fh.close()
##########
SYMBOLS = {
    'customary'     : ('B', 'KB', 'MB', 'GB', 'T', 'P', 'E', 'Z', 'Y'),
}
def bytes2human(n, format='%(value).2f %(symbol)s', symbols='customary'):
    n = int(n)
    if n < 0:
        raise ValueError("n < 0")
    symbols = SYMBOLS[symbols]
    prefix = {}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i+1)*10
    for symbol in reversed(symbols[1:]):
        if n >= prefix[symbol]:
            value = float(n) / prefix[symbol]
            return format % locals()
    return format % dict(symbol=symbols[0], value=n)
##########


parser = argparse.ArgumentParser()
parser.add_argument('-outputdir', action='store', dest='output_dir', help='The custom output directory to store output in, if desired')
parser.add_argument('-nodownload', action='store_false', default=True, dest='download', help='Turn OFF content downloading - will not generate CIA files.')
parser.add_argument('-nobuild', action='store_false', default=True, dest='build', help='Turn OFF generation of CIA files, titles will be downloaded only.')
parser.add_argument('-retry', type=int, default=4, dest='retry_count', choices=range(0, 10), help='How many times a file download will be attempted')
parser.add_argument('-titleid', action='store', dest='titleid', help='Title ID of the content you want to download')
parser.add_argument('-key', action='store', dest='key', help='Encrypted Title Key for the Title ID')
arguments = parser.parse_args()

tk = 0x140
badinput = False
error = False

if (arguments.titleid is None) or (arguments.key is None):
    print 'You need to enter a Title ID and Encrytped Title Key'
    sys.exit(0)


if arguments.titleid is not None:
        if (len(arguments.titleid) is 16) and all(c in string.hexdigits for c in arguments.titleid):
            pass
        else:
            print 'The Title ID(s) must be 16 hexadecimal characters long'
            print arguments.titleid + ' - is not ok.'
            print ''
            badinput = True

if arguments.key is not None:
    if (len(arguments.key) is 32) and all(c in string.hexdigits for c in arguments.key):
        pass
    else:
        print 'The Encrytped Title Key must be 32 hexadecimal characters long'
        print arguments.key + ' - is not ok.'
        print ''
        badinput = True
if badinput: #if any input was not ok, quit
    sys.exit(0)



print '*******\nFunKeyCIA by cearp\n*******\n'


tikdata = bytearray(tiktem)
tikdata[tk+0x9C:tk+0xA4] = binascii.a2b_hex(arguments.titleid)
tikdata[tk+0x7F:tk+0x8F] = binascii.a2b_hex(arguments.key)

if(arguments.output_dir is not None):
    rawdir = os.path.join(arguments.output_dir, 'raw', arguments.titleid)
    ciadir = os.path.join(arguments.output_dir, 'cia', arguments.titleid)
else:
    rawdir = os.path.join('raw', arguments.titleid)
    ciadir = os.path.join('cia', arguments.titleid)

if not os.path.exists(rawdir):
    os.makedirs(os.path.join(rawdir))



#download stuff
if(arguments.download):
    print 'Downloading TMD...'

    baseurl = 'http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/' + arguments.titleid

    for attempt in range(arguments.retry_count+1):
        try:
            if(attempt > 0):
                print '*Attempt ' + str(attempt+1) + ' of ' + str(arguments.retry_count+1)
            tmd = urllib2.urlopen(baseurl + '/tmd')
        except urllib2.URLError, e:
            print 'Could not download TMD...'
            error = True
            continue
        error = False
        print 'Downloaded TMD OK!'
        break
    
    if error:
        print 'ERROR: Could not download TMD. Skipping title...\n'

    if not error:

        print ''

        tmd = tmd.read()
        tikdata[tk+0xA6:tk+0xA8] = tmd[tk+0x9C:tk+0x9E]
        open(os.path.join(rawdir, 'cetk'),'wb').write(tikdata+magic)
        open(os.path.join(rawdir) + '/tmd','wb').write(tmd)

        #download stuff
        print 'Downloading Contents...'

        contentCount = int(binascii.hexlify(tmd[tk+0x9E:tk+0xA0]),16)

        for i in xrange(contentCount):
            if not error:
                cOffs = 0xB04+(0x30*i)
                cID = binascii.hexlify(tmd[cOffs:cOffs+0x04])
                print 'Downloading ' + str(i+1) + ' of ' + str(contentCount) + '. This file is ' + bytes2human(int(binascii.hexlify(tmd[cOffs+0x08:cOffs+0x10]),16))
                outfname = os.path.join(rawdir, cID)
                
                for attempt in range(arguments.retry_count+1):
                    try:
                        if(attempt > 0):
                            print 'Attempt ' + str(attempt+1) + ' of ' + str(arguments.retry_count+1)
                        response = urllib2.urlopen(baseurl + '/' + cID)
                        chunk_read(response, outfname, report_hook=chunk_report)
                        if (int(os.path.getsize(outfname)) != int(binascii.hexlify(tmd[cOffs+0x08:cOffs+0x10]),16) ):
                            print 'Content download not correct size\n'
                            continue
                    except urllib2.URLError, e:
                        print 'Could not download content file...\n'
                        error = True
                        continue
                    error = False
                    break
                
                if error:
                    print 'ERROR: Could not download content file... Skipping title'             
                print ''
        

        if not error:
            print 'Title download complete\n'

            #cia generation
            if(arguments.build):
                if not os.path.exists(ciadir):
                    os.makedirs(ciadir)
                makecommand = ' ' + os.path.join(rawdir) + ' ' + os.path.join(ciadir, arguments.titleid) + '.cia'
                os.system(execname + makecommand)
                if(os.path.isfile(os.path.join(ciadir, arguments.titleid) + '.cia')):
                    print 'CIA created ok!'
                else:
                    print 'CIA not created...'
                print ''
                print ''


