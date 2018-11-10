#Taken from https://github.com/feliam/miniPDF
import struct

#For constructing a minimal pdf file
class PDFObject:
    def __init__(self):
        self.n=None
        self.v=None
           
    def __str__(self):
        s="%d %d obj\n"%(self.n,self.v)
        for t in self.toks:
            s+=t.__str__()
        s+="\nendobj" 
        return s

class PDFStream(PDFObject):
    def __init__(self, dict,stream):
        PDFObject.__init__(self)
        dict.add('Length', len(stream))
        self.dict=dict
        self.stream=stream

    def __str__(self):
        s=""
        s+=self.dict.__str__()
        s+="\nstream\n"
        s+=self.stream
        s+="\nendstream"
        return s

class PDFArray(PDFObject):
    def __init__(self,s):
        PDFObject.__init__(self)
        self.s=s
    def __str__(self):
        return "[%s]"%(" ".join([ o.__str__() for o in self.s]))


class PDFDict(PDFObject):
    def __init__(self):
        PDFObject.__init__(self)
        self.dict = []    

    def add(self,name,obj):
        self.dict.append((name,obj))

    def __str__(self):
        s="<<\n"
        for name,obj in self.dict:
            s+="/%s %s\n"%(name,obj)
        s+=">>"
        return s    

class PDFName(PDFObject):
    def __init__(self,s):
        PDFObject.__init__(self)
        self.s=s
    def __str__(self):
        return "/%s"%self.s

class PDFString(PDFObject):
    def __init__(self,s):
        PDFObject.__init__(self)
        self.s=s

    def __str__(self):
        return "(%s)"%self.s

class PDFHexString(PDFObject):
    def __init__(self,s):
        PDFObject.__init__(self)
        self.s=s

    def __str__(self):
        return "<" + "".join(["%02x"%ord(c) for c in self.s]) + ">"

class PDFOctalString(PDFObject):
    def __init__(self,s):
        PDFObject.__init__(self)
        self.s="".join(["\\%03o"%ord(c) for c in s])

    def __str__(self):
        return "(%s)"%self.s

class PDFNum(PDFObject):
    def __init__(self,s):
        PDFObject.__init__(self)
        self.s=s

    def __str__(self):
        return "%s"%self.s

class PDFRef(PDFObject):
    def __init__(self,obj):
        PDFObject.__init__(self)
        self.obj=[obj]
    def __str__(self):
        return "%d %d R"%(self.obj[0].n,self.obj[0].v)

class PDFNull(PDFObject):
    def __init__(self):
        PDFObject.__init__(self)

    def __str__(self):
        return "null"


class PDFDoc():
    def __init__(self):
        self.objs=[]
    
    def setRoot(self,root):
        self.root=root

    def setInfo(self,info):
        self.info=info
            
    def _add(self,obj):
        obj.v=0
        obj.n=1+len(self.objs)
        self.objs.append(obj)

    def add(self,obj):
        if type(obj) != type([]):
            self._add(obj);        
        else:
            for o in obj:  
                self._add(o)

    def _header(self):
        return "%PDF-1.5\n"
    
    def __str__(self):
        doc1 = self._header()
        xref = {}
        for obj in self.objs:
            xref[obj.n] = len(doc1)
            doc1+="%d %d obj\n"%(obj.n,obj.v)
            doc1+=obj.__str__()
            doc1+="\nendobj\n" 
        posxref=len(doc1)
        doc1+="xref\n"
        doc1+="0 %d\n"%len(self.objs)
        doc1+="0000000000 65535 f\n"
        for xr in xref.keys():
            doc1+= "%010d %05d n\n"%(xref[xr],0)
        doc1+="trailer\n"
        trailer =  PDFDict()
        trailer.add("Size",len(self.objs))
        trailer.add("Root",PDFRef(self.root))
        #trailer.add('Encrypt', "6 0 R")
#        trailer.add("Info",PDFRef(self.info))
        doc1+=trailer.__str__()
        doc1+="\nstartxref\n%d\n"%posxref    
        doc1+="%%EOF\n\n"        

        return doc1


