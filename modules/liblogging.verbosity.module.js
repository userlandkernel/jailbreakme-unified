//@enum VERBOSITY
var VERBOSITY = {
	NONE: 0,
	LOW: 1,
	DEFAULT: 2,
	HIGH: 3,
	VERBOSE: 4
};

//Set the verbosity to the default verbosity
if(typeof verbosity === 'undefined') verbosity = VERBOSITY.DEFAULT;
