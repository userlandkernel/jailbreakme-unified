/*
 *  Device Support Module
 *  Can detect iOS Device properties by various algorithms
*/
using('libcrypto');
using('libstorage');

var detectRouter = function() {
    var default_ips = [
        '192.168.0.1',
        '192.168.0.2',
        '192.168.1.1',
        '192.168.1.2',
        '192.168.1.10',
        '192.168.1.99',
        '192.168.1.210',
        '192.168.1.254',
        '192.168.2.1',
        '192.168.3.1',
        '192.168.8.1',
        '192.168.15.1',
        '192.168.16.1',
        '192.168.100.1',
        '192.168.123.254',
        '192.168.254.254',
        '10.0.0.2',
        '10.0.0.138',
        '10.0.1.1',
        '10.1.1.1',
        '10.10.1.1'
    ];
    var found_ips = new Array();
    for(i = 0; i < default_ips.length; i++) {
        var ip = default_ips[i];
        try{
            var contents = FileStorage.getcontents(FileStorage.mode.XML, 'https://'+ip+'/');
            if(contents) found_ips.push(ip);
        } catch(e) {
            console.log('No router at '+ip);
        }
    }
    return found_ips.join(',');
};

function debug_mkeligible(){
    window.chosendevice.Browser.mobilesafari = true; 
    window.chosendevice.ProductName = "iPhone 6S"; 
    window.chosendevice.DeviceType = "iPhone"; 
    window.chosendevice.OSVersion = 11.31;
    window.supported_osversion = function(){return true;};
}


var MobileEnvironmentDetails = function MobileEnvironmentDetails() {
    this.AppleiOS = (
        navigator.userAgent.indexOf('iPad')     >= 0 ||  
        navigator.userAgent.indexOf('iPhone')   >= 0 || 
        navigator.userAgent.indexOf('iPod')     >= 0
    );
    this.Homescreened = window.navigator.standalone ? true : false;
    this.Orientation = (
        window.orientation === 90 || window.orientation === -90
    ) ? "landscape" : "portrait";
    this.Webviewed = (
        this.AppleiOS                                    && 
        navigator.userAgent.indexOf('AppleWebKit')  >= 0 && 
        navigator.userAgent.indexOf('Safari')       >= 0
    );
    this.Statusbarred = this.Webviewed && window.innerWidth * window.innerHeight  === screen.width * screen.height;
};

//Function for detecting the dots per inch of the screen
function detectDPI(w, h) {
    var dppx = window.devicePixelRatio || (window.matchMedia && window.matchMedia("(min-resolution: 2dppx), (-webkit-min-device-pixel-ratio: 1.5),(-moz-min-device-pixel-ratio: 1.5),(min-device-pixel-ratio: 1.5)").matches? 2 : 1) || 1;
    w = w * dppx;
    h = h * dppx;
    w > 0 || (w = 1);
    h > 0 || (h = 1);
    var dpi = Math.sqrt(w * w + h * h);
    return dpi > 0 ? Math.round(dpi) : 0;
}

//Functions for getting the Local IP address of the client
function await_getipv4(timeout = 1000) {
    var t1 = new Date();
    while(!window.ipv4) {
        var stop = new Date() - t1 >= timeout;
        if(stop) {
            console.error('timeout exceeded for await_getipv4.');
            return "0.0.0.0";
        }
    }
    return window.ipv4;
}

function async_getipv4() {
    var ipv4 = null;
    var findIP = new Promise(r=>{var w=window,a=new (w.RTCPeerConnection||w.mozRTCPeerConnection||w.webkitRTCPeerConnection)({iceServers:[]}),b=()=>{};a.createDataChannel("");a.createOffer(c=>a.setLocalDescription(c,b,b),b);a.onicecandidate=c=>{try{c.candidate.candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/g).forEach(r)}catch(e){}}})
    findIP.then(ip => window.ipv4 = ip);
    return await_getipv4();
};

//Class for getting the Display specifications of the client
var ScreenSpecs = function ScreenSpecs(width, height, dpi) {
    this.retina = (window.devicePixelRatio || 1) >= 2;
    this.width = width || window.screen.width || -1;
    this.height = height || window.screen.height || -1;
    this.dpi = dpi || detectDPI(this.width, this.height);
    this.touchscreen = navigator.maxTouchPoints || navigator.msMaxTouchPoints || 'ontouchstart' in window;
    this.toString = function() {
        return JSON.stringify(this);
    };
}

//Function for parsing the GPU name to a simple Apple standard.
function parseGPU(gpu) {
    if(!gpu) return "Unknown GPU";
    if(gpu) gpu = gpu.split('Apple ');
    if(gpu.length > 1) gpu = gpu[1].split(' GPU')[0];
    return gpu;
}

//Class for getting the graphicscard's specifications
var GPUSpecs = function GPUSpecs() {
    var ctx = document.createElement('canvas');
    if(!ctx.getContext) return "Unknown GPU";
    var gl = ctx.getContext('experimental-webgl');
    if(!gl) gl = ctx.getContext('webgl');
    if(!gl) return false;
    if(!gl.getExtension || !gl.getParameter) return false;
    debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if(!debugInfo) return false;
    vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
    renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
    if(!vendor || !renderer) return false;
    this.Name = parseGPU(renderer);
    this.Vendor = vendor;
    this.VRAM = 'NaN';
};


//Class for getting the Processor's specifications
var CPUSpecs = function CPUSpecs(name, vendor, clockspeed, cores, threads, bits) {
    this.Name = name || 'Unknown Processor';
    this.Vendor = vendor || 'Unknown Vendor';
    this.clockspeed = clockspeed || 'NaN';
    this.cores = cores  || navigator.hardwareConcurrency || 'NaN';
    this.threads = threads || 'NaN';
    this.bits = bits || 'NaN';
    this.toString = function() {
        return JSON.stringify(this);
    };
}

//Class for getting the Memory's specifications
var RAMSpecs = function RAMSpecs(free, used, wired, maximumheap) {
    this.Free = free || 'NaN';
    this.Used = used || 'NaN';
    this.Wired = wired || 'NaN';
    this.HeapMax = maximumheap || 'NaN';
    this.toString = function() {
        JSON.stringify(this);
    };
}

//Constant class for getting all hardware specifications from the client
function detectHardwareSpecs(){
    return {
        screen: new ScreenSpecs(),
        graphics: new GPUSpecs(),
        cpu: new CPUSpecs(),
        memory: new RAMSpecs()
    };
};

//Class for getting the browser specifications from the client.
var BrowserSpecs = function BrowserSpecs() {
    this.mobile = (typeof window.orientation !== "undefined") || (navigator.userAgent.indexOf('IEMobile') !== -1);
    this.safari = window.navigator.userAgent.indexOf('Safari') > -1;
    this.mobilesafari = this.mobile && this.safari;
    this.webkit = window.navigator.userAgent.indexOf('AppleWebKit') > -1;
    this.nvers = parseFloat(navigator.appVersion);
    this.agent = navigator.userAgent;
    this.name = navigator.appName || "";    
    this.nickname = navigator.appCodeName || "";
    this.platform = navigator.platform || "Unknown platform";
    this.safari_vers = window.navigator.userAgent.indexOf('Safari') > -1 ? parseFloat(window.navigator.userAgent.split('Version/')[1]) : null;
    this.webkit_vers = /AppleWebKit\/([\d.]+)/.exec(navigator.userAgent);
    if(this.webkit_vers) this.webkit_vers = parseFloat(this.webkit_vers[1]);
    this.toString = function() {
        return JSON.stringify(this);
    };

};

//Class for getting the localization specifications from the client.
var LocaleSpecs = function LocaleSpecs() {
    this.locale = navigator.systemLanguage || navigator.language;
    this.timezone = new Date().toString().match(/([A-Z]+[\+-][0-9]+)/)[1];
    this.toString = function() {
        return JSON.stringify(this);
    };
};


//Algorithm for detecting the iOS Firmware build version using the userAgent
function detectBuild() {
    var tmp = navigator.userAgent.indexOf('Mobile/') > -1;
    if(tmp) {
        tmp = navigator.userAgent.split('Mobile/');
        if(tmp.length<1) return null;
        return tmp[1].split(' ')[0];
    }
    return null;
}

//Algorithm for detecting the iOS version using the userAgent
function detectOSVersion() {
     var match = (navigator.appVersion).match(/OS (\d+)_(\d+)_?(\d+)?/);
      if(match) {
        var version = [
            parseInt(match[1], 10),
            parseInt(match[2], 10),
            parseInt(match[3] || 0, 10)
        ];
        return parseFloat(version[0]+'.'+version[1]+version[2]);
      }
      return false;
}

//Algorithm for converting iOS build numbers to iOS OS Versions or iOS OS Versions to build numbers
function convertBuild(str) {
    if(typeof str !== 'string' && typeof str !== 'number') return null;
    var build = [];
    build['15E148'] = 12.01;
    build['15F79'] = 11.4;
    build['15E302'] = 11.31;
    build['15E216'] = 11.301;
    build['15E148'] = 11.300;
    build['15D100'] = 11.26;
    build['15D60'] = 11.22;
    build['15C153'] = 11.21;
    build['15C114'] = 11.2;
    build['15B202'] = 11.12;
    build['15B150'] = 11.11;
    build['15B93'] = 11.1;
    build['15A432'] = 11.03;
    build['15A421'] = 11.02;
    build['15A402'] = 11.01;
    build['15A372'] = 11.0;
    build['14G60'] = 10.33;
    build['14F89'] = 10.32;
    build['14E302'] = 10.31;
    build['14E277'] = 10.3;
    build['14D27'] = 10.21;
    build['14C92']= 10.2;
    build['14B150'] = 10.111;
    build['14B100'] = 10.110;
    build['14B72'] = 10.1;
    build['14A456'] = 10.02;
    build['14A403'] = 10.01;
    build['13G36'] = 9.35;
    build['13G35'] = 9.34;
    build['13G34'] = 9.33;
    build['13F69'] = 9.32;
    build['13E238'] = 9.31;
    build['13E233'] = 9.3;
    build['13D20'] = 9.211;
    build['13D15'] = 9.210;
    build['13C75'] = 9.2;
    build['13B143'] = 9.1;
    build['13A452'] = 9.02;
    build['13A404'] = 9.01;
    build['13A344'] = 9.0;
    build['12H321'] = 8.41;
    build['12H143'] = 8.4;
    build['12F70'] = 8.3;
    build['12B466'] = 8.13;
    build['12B440'] = 8.12;
    build['12B436'] = 8.11;
    build['12B411'] = 8.1;
    build['12A405'] = 8.02;
    build['12A402'] = 8.01;
    build['12A365'] = 8.0;
    
    if(build[str]) {
        return build[str];
    }

    for(var prop in build) {
        if(build.hasOwnProperty(prop)) {
            if(build[prop] === str) {
                return prop;
            }
        }
    }

    return false;
}


//Algorithm for detecting the device type from the userAgent
function detectDeviceType() {
    
    if(navigator.userAgent.indexOf('iPhone') > -1) {
        return "iPhone";
    }

    if(navigator.userAgent.indexOf('iPad') > -1) {
        return "iPad";
    }

    if(navigator.userAgent.indexOf('iPod') > -1) {
        return "iPod";
    }

    return "UnitTest";
}


// Algorithm for detecting the productname of the iOS client device based on producttype, resolution and GPU.
// Yes, I know, there's no AppleTV and iPod yet but feel free to add that logic.
// I'll need to rewrite this logic to parse from either JSON or Plist one day
function detectProductName(t, width, height, gpu) {

    if(!t && !width && !height && !gpu) return false; //performance optimalisation

    var dpi = detectDPI(width, height);


    if(t === "iPhone") {
        if(height <= 480) return ['iPhone 2G', 'iPhone 3', 'iPhone 3GS'];

        if(width === 320 && height === 480 && gpu =='A4') return ['iPhone 4'];
        
        if(width === 320 && height === 480 && gpu == 'A5') return ['iPhone 4S'];
        if(width === 320 && height === 568 && gpu == 'A5') return ['iPhone 5'];
        
        if(width === 320 && height === 568 && gpu == 'A6') return ['iPhone 5C'];
        
        if(width === 320 && height === 568 && gpu == 'A7') return ['iPhone 5S'];
        
        if(width === 375 && height === 667 && gpu == 'A8') return ['iPhone 6'];
        if(width === 414 && height === 736 && gpu == 'A8') return ['iPhone 6+'];
        
        if(width === 375 && height === 667 && gpu == 'A9') return ['iPhone 6S'];
        if(width === 414 && height === 736 && gpu == 'A9') return ['iPhone 6S+'];
        if(width === 320 && height === 568 && gpu == 'A9') return ['iPhone SE'];
        
        if(width === 375 && height === 667 && gpu == 'A10') return ['iPhone 7'];
        if(width === 414 && height === 736 && gpu == 'A10') return ['iPhone 7+'];
        
        if(width === 375 && height === 667 && gpu == 'A11') return ['iPhone 8'];
        if(width === 414 && height === 736 && gpu == 'A11') return ['iPhone 8+'];
        if(width === 375 && height === 812 && gpu == 'A11') return ['iPhone X'];
    }

    else if(t === "iPad") {
        /* iPads */
        if(width === 768 && height === 1024 && gpu == 'A5') return ['iPad Mini', 'iPad 2'];
        
        if(width === 768 && height === 1024 && gpu == 'A7') return ['iPad Mini 2', 'iPad Mini 3', 'iPad Air'];
        
        if(width === 768 && height === 1024 && gpu == 'A8') return ['iPad Mini 4'];
        
        if(width === 768 && height === 1024 && gpu == 'A5X') return ['iPad 3'];
        
        if(width === 768 && height === 1024 && gpu == 'A6X') return ['iPad 4'];
        
        if(width === 768 && height === 1024 && gpu == 'A8X') return ['iPad Air 2'];
        
        if(width === 768 && height === 1024 && gpu == 'A9X') return ['9.7-inch iPad Pro'];
        
        if(width === 768 && height === 1024 && gpu == 'A10') return ['iPad 6 (Cellular)'];

        if(width === 834 && height === 1112 && gpu == 'A10X') return ['10.5-inch iPad Pro'];
        if(width === 1024 && height === 1366 && gpu == 'A10X') return ['12.9-inch iPad Pro'];
    
    } else {
    
        if(width === 272 && height === 340 && gpu == 'S1') return ['Watch 1 38mm'];
        if(width === 312 && height === 390 && gpu == 'S1') return ['Watch 1 42mm'];
        
        if(width === 272 && height === 340 && gpu == 'S1P') return ['Watch 1 sport 38mm'];
        if(width === 312 && height === 390 && gpu == 'S1P') return ['Watch 1 sport 42mm'];
        
        if(width === 272 && height === 340 && gpu == 'S2') return ['Watch 2 38mm'];
        if(width === 312 && height === 390 && gpu == 'S2') return ['Watch 2 42mm'];
        
        if(width === 272 && height === 340 && gpu == 'S3') return ['Watch 3 38mm'];
        if(width === 312 && height === 390 && gpu == 'S3') return ['Watch 3 42mm'];
    }
    
    return false;
}

//check whether the architecture of the device is 32-bit or 64-bit
function DetectArchitecture(productname, version) {
    if(version >= 11) return 64;
    if(version <= 4.9) return 32;

    var x32_devices = [
        'iPhone 2G',
        'iPhone 3G',
        'iPhone 3GS',
        'iPhone 4',
        'iPhone 4S',
        'iPhone 5',
        'iPhone 5C',
        'iPad Mini',
        'iPad 2'
    ];

    var bits = 64;
    
    for(i = 0; i < productname.length && bits!=32; i++) {
        bits = (x32_devices.indexOf(productname[i]) != -1) ? 32 : 64;
    }

    return bits;
}

//Class for constructing a device and all of it's information
var Device = function Device(name, type, productname, osversion, build, browser, localization, hardware, identifier) {
    this.Name = name || 'UnitTest Device';
    this.DeviceType = type || detectDeviceType();
    this.Hardware = detectHardwareSpecs();
    this.OSVersion = detectOSVersion() || "";
    this.Build = detectBuild() || convertBuild(this.OSVersion);
    this.Browser = new BrowserSpecs();
    this.Localization = new LocaleSpecs();
    this.ProductName = productname || detectProductName(this.DeviceType, this.Hardware.screen.width, this.Hardware.screen.height, this.Hardware.graphics.Name);
    this.Architecture = DetectArchitecture(this.ProductName, this.OSVersion);
    this.identifier = Sha1.hash(JSON.stringify(this));
    this.toString = function() {
        return JSON.stringify(this);
    };
};


//returns the current device or gets the current device through detection
function current_device() {
    if(window.chosendevice) {
        return window.chosendevice;
    } else {
        window.chosendevice = new Device('Production device');
        return window.chosendevice;
    }
}




