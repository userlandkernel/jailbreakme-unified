var LIBASYNC = true;

var async_wait = function(objname) 
{
	var t1 = new Date();
	var t2 = new Date();
	var tr = 0;

	var inline_should_await = function(objname) 
	{
		try {
			var obj = eval(objname);
			return typeof obj !== 'undefined' ? false : true;
		} catch(e) {
			return true;
		}
		return true;
	};

	while(inline_should_await(objname))
	{
		t2 = new Date();
		tr = t2 - t1;
		shouldstop = (tr >= 1000);
		if(shouldstop)
		{
			console.log('[Async_wait]: timeout exceeded.');
			return false;
		}
	}
	console.log('[Async_wait]: got objname in T.'+tr);
	return true;
}