var LIBSPLOIT_STRATEGY = true;
/***
 *         ██╗ █████╗ ██╗██╗     ██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗    ███╗   ███╗███████╗
 *         ██║██╔══██╗██║██║     ██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝    ████╗ ████║██╔════╝
 *         ██║███████║██║██║     ██████╔╝██████╔╝█████╗  ███████║█████╔╝     ██╔████╔██║█████╗
 *    ██   ██║██╔══██║██║██║     ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗     ██║╚██╔╝██║██╔══╝
 *    ╚█████╔╝██║  ██║██║███████╗██████╔╝██║  ██║███████╗██║  ██║██║  ██╗    ██║ ╚═╝ ██║███████╗
 *     ╚════╝ ╚═╝  ╚═╝╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝     ╚═╝╚══════╝
 *
 *    A collection of public exploits by various security researchers chained together to escallate to kernel privileges from a website, with as final payload a jailbreak including post-exploitation utillities such as the Cydia Package manager and a remote shell server.
 */

/*
     Credits:
     - Comex for his ancient but awesome jailbreakme.
     - Luca Todesco (Jailbreak Me with his own webkit exploit and Pangu's IOMobileFramebuffer kernel exploit)
     - Tihmstar for his 9.1 - 9.3.4 jailbreakme
     - Niklas B and Phoenhex for CVE-2018-4233 and the awesome exploit development kit and writeup
     - Ian Beer for his amazing work, writeups and full-exploits. In specific for the empty_list exploit
     - Jonathan Levin for his Jailbreak Toolkit
     - The webkit foundation for having the awesome feature of retrieving the client's GPU model through javascript
     - Apple Inc. for patching these vulnerabilities. As they are of severe impact to security of iOS devices.
 */

/*
    Contibutions:
    - Feel free to contribute to this exploit but mention all authors, they deserve that.
    - Please initialize all variables, this keeps the exploits stable
 */

module('libsploit.ios.offsets'); //for offsets detection
module('libdetect'); //for client device detection
module('liblogging'); //for verbosity functionality

//Configures the maximum supported operating system version or safari version
var MAX_SUPPORT = {
    os: 12.01,
    safari: 604.1
};

//prints out specifications of a detected device
function print_specifications() {
   var device = current_device();
   puts('<b>'+device.ProductName+'</b>');
   puts('<b>OS: </b>'+device.OSVersion);
   puts('<b>Build: </b>'+device.Build);
   puts('<b>Webkit version: </b>'+device.Browser.webkit_vers);
   puts('<b>DID: </b><br>'+device.identifier);
}

//returns whether the exploit supports the client's browser or not
function supported_browser() {
    var device = current_device();
    return device.Browser.mobilesafari;
}

//returns whether the exploit supports the client's device type
function supported_devicetype() {
    var device = current_device();
    return device.DeviceType === "iPhone" || device.DeviceType === "iPad" || device.DeviceType === "iPod";
}

//returns whether the exploit supports the client's os version
function supported_osversion() {
    var device = current_device();
    return (device.OSVersion <= MAX_SUPPORT.os) && (device.Browser.safari_vers <= MAX_SUPPORT.safari);
}

//returns whether the exploit needs offsets for the client device
function needs_offsets() {
    var device = current_device();
    return device.OSVersion >= 10 && device.OSVersion <= 12.01;
}

//returns whether the model and os version of the client were recognized
function did_recognize() {
    var device = current_device();
    return (device.ProductName && device.OSVersion);
}

//returns true when the client's os version is inclusively between the specified minimum and maximum value
function osversion_between(min, max) {
    var device = current_device();
    return device.OSVersion >= min && device.OSVersion <= max;
}


//sets the offsets for the client's device and returns true or false depending on the succession of it
function offsets_init() {
    var device = current_device();
    device.offsets = Offsets(device.OSVersion, device.ProductName);
    if(!device.offsets) {
        puts("Missing offsets for "+device.ProductName+" on "+device.OSVersion);
        device.offsets = {};
        return false;
    }
    return true;
}

//performs initial eligibillity checks to determine if the client's device is one that the exploit supports
function sploit_init() {
    var device  = current_device();
    
    if(!supported_browser()) {
        puts("This exploit only works on MobileSafari.");
        return false;   
    }

    if(!supported_devicetype()) {
        puts("This exploit only works on iOS devices.");
        return false;
    }

    if(!supported_osversion()) {
        puts("iOS higher than "+MAX_SUPPORT.os+" is not supported.");
        return false;
    }

    if(!did_recognize()) {
        puts("Could not recognize what device this is, are you sure this is iPhone?");
    }

    if(needs_offsets()) {
        if(!offsets_init()) { //Attmempt to get the offsets of the device, in case of failure return false
            return false;
        }
    }

    print_specifications();

    return true;
}



//Loading modules takes time therefore this is an implementation of an async-await javascript function
function start_strategy(name) {
    window.await = setInterval(function(){
        if(eval(name) !== undefined) {
            eval(name+"();");
            clearInterval(window.await);
        }
    }, 250);
}

//Based on the detected device constraints the exploit to be used can be determined.
function strategy_select() {
    var device = current_device();
    if(!device) return false; //sanity check, in theory current_device() always returns a device


    if(osversion_between(3.12, 4.01)) {
        puts('Chose star/saffron.');
        include('libsploit.ios.legacy');
        start_strategy('ancientgo');
        return true;
    }

    else if(osversion_between(7.1, 7.12)) {
        puts('Chose CG Gangster exploit.');
        include('libsploit.ios.71');
        start_strategy('cg7go');
        return true;
    }

    else if(osversion_between(9.0, 9.34)) {
        puts('Chose Tihmstar jbme');
        include('libsploit.ios.91x32');
        start_strategy('wk91go');
        return true;
    }

    else if(osversion_between(11.3, 11.31)) {

        //We firstly need to check if the client's device model is of one that this strategy supports
        var supported_devices = ["iPhone X", "iPhone 8", "iPhone 8+", "iPhone 6S", "iPhone 6+", "iPhone 5S"];
        var supported = false;

        if(!device.ProductName) return false; //Sanity check making sure to only continue if the product name of the device was detected

        //The productname detection may return multiple results.
        //Check each individual entry against the supported devices array and stop the search when a supported device is found.
        for(var i = 0; i < supported_devices.length && supported == false; i++) {
            supported = device.ProductName.indexOf(supported_devices[i]) > -1;
        }

        //Sanity check to only start the strategy when the exploit supports the client's device
        if(supported) {
            
            puts('Chose Niklas B\'s jailbreakme');
            include('libsploit.ios.1131'); //include the strategy module
            start_strategy('wk113go'); //schedule the strategy for launch
            return true;

        } else {
            puts('Your '+(device.ProductName ? device.ProductName.join(' or ') : 'Unknown device') + " is not supported"); //There is no exploit available for the client's device
            return false;
        }
    }
    else if(osversion_between(11.41,11.41)) {
         //We firstly need to check if the client's device model is of one that this strategy supports
        var supported_devices = ["iPhone 6", "iPhone SE"];
        var supported = false;

        if(!device.ProductName) return false; //Sanity check making sure to only continue if the product name of the device was detected
        
        //The productname detection may return multiple results.
        //Check each individual entry against the supported devices array and stop the search when a supported device is found.
        for(var i = 0; i < supported_devices.length && supported == false; i++) {
            supported = device.ProductName.indexOf(supported_devices[i]) > -1;
        }

        if(supported) {
            
            puts('Chose Kuduma\'s jailbreakme');
            include('libsploit.ios.1141'); //include the strategy module
            start_strategy('wk1141go'); //schedule the strategy for launch
            return true;

        } else {
            puts('Your '+(device.ProductName ? device.ProductName.join(' or ') : 'Unknown device') + " is not supported"); //There is no exploit available for the client's device
            return false;
        }
    }
    else if(osversion_between(12.0, 12.01)){

         //We firstly need to check if the client's device model is of one that this strategy supports
        var supported_devices = ["iPhone 6S", "iPhone SE", "iPhone 8+"];
        var supported = false;

        if(!device.ProductName) return false; //Sanity check making sure to only continue if the product name of the device was detected

        //The productname detection may return multiple results.
        //Check each individual entry against the supported devices array and stop the search when a supported device is found.
        for(var i = 0; i < supported_devices.length && supported == false; i++) {
            supported = device.ProductName.indexOf(supported_devices[i]) > -1;
        }
        
        if(supported) {
            
            puts('Chose Kuduma\'s jailbreakme');
            include('libsploit.ios.1201'); //include the strategy module
            start_strategy('wk1201go'); //schedule the strategy for launch
            return true;

        } else {
            puts('Your '+(device.ProductName ? device.ProductName.join(' or ') : 'Unknown device') + " is not supported"); //There is no exploit available for the client's device
            return false;
        }
    }
    return false;
}

//The main function is the function that should be called manually, all other functions are private functions
function sploit_main() {

    //A try-catch exception handler providing continuity and verbosity to the runtime
    try {
        
        //Firstly make sure that the initialization stage where eligibility is checked has succeeded, otherwise we exit.
        if(!sploit_init()) {
            puts('Exploit initialization failed');
            return false;
        }

        //request the detected device and select a strategy for it
        var device = current_device();
        var strategy = strategy_select(); //this will not only select a strategy but also schedule it for launch as soon as posisble/

        //A second try-catch gives a better inside in which stage an error occured if one occured.
        try{ 

            if(!strategy) {
                puts("Your device or ios version isn't supported.");
                return false;
            }

        } catch(exc) {
           alert('Exploit failed: \n\nStack trace: \n\n'+exc.stack+'\n\nReason:'+exc.message); //The exception occurred in the exploit, show the user a stack-trace
        }

    } catch(exc) {
        alert('Exception occured:\n\nStack trace: \n\n'+exc.stack+'\n\nReason:'+exc.message); //An unknown exception occured in the program, show the user a stack-trace
    }

    return true;
}

