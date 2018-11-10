import sys, struct
#See PORTING

def js(a1,a2,a3,base):
    return '''{ "byte0": 0x%02x, "byte1": 0x%02x, "byte2": 0x%02x, 
                                                    "version": "$VERSION$", 
                                                    "dyld_shared_cache_offset": 0x%08x },
'''% ( a1&0xff, a2&0xff, a3&0xff, a1- base )

cache = file(sys.argv[1],'rb').read()
a1,a2,a3 = struct.unpack('<LLL',   ''.join(sys.argv[2:]).decode('hex') )

assert a1 < a2 and a2 < a3 
print "Live Pointers 0x%08x 0x%08x 0x%08x "%(a1,a2,a3)
for i in xrange(a1&0xfff, len(cache),0x1000):
    #print "%08x"%i
    if i&0xfff == a1&0xfff and \
        cache[i-1] == '\x90' and cache[i] == '\xb5' and \
        cache[a2-a1+i-1] == '\xf0' and cache[a2-a1+i] == '\xb5' and \
        cache[a3-a1+i-1] == '\x00' :
        print "Possible dyld_shared_cache base: 0x%x"%(a1-i)
        print js(a1,a2,a3, a1-i)


#print "0x%08x"%cache.find("\xf0\x6d\xb0\xe8\x10\x8b")

