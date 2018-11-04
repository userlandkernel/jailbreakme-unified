
/* 
 *	This function is used for dumping an amount of memory from a given address
 *
 */
var memorydump = function(vm_addr_base = 0, vm_size = 0, primitive = false)
{
	//Initial variables
	var maxrow_width = 16;
	var current_addr = vm_addr_base;
	var output = new String("0x"+current_addr.toString(16)+": ");

	//Sanity check for the primitive function and size arguments
	if(!primitive || vm_size <= 0) return;

	//Read the size of bytes from the addresses
	for(rowindex = 1, current_addr = vm_addr_base; (current_addr - vm_addr_base) < vm_size; current_addr++, rowindex++)
	{
		console.log(current_addr.toString(16));
		var readval = primitive.read(current_addr, 1); //read one byte from the current address
		output += String.fromCharCode(readval); //convert uint8 -> char and add it to the output
		if(rowindex === maxrow_width) {
			output += "\n";
			output += "0x"+(current_addr+1).toString(16)+": ";
			rowindex = 0;
		}
	}
	return output;
};