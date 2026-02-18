#include "../obfuscator.h"

bool obfuscator::obfuscate_ff(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	// EB 01 = JMP +1 (skips over the dead byte to the original FF instruction)
	instruction_t jmp_over{}; jmp_over.load(function->func_id, { 0xEB, 0x01 });
	jmp_over.isjmpcall = false;
	jmp_over.has_relative = false;

	// Dead byte: INT3 (never executed, confuses linear disassembly)
	instruction_t dead_byte{}; dead_byte.load(function->func_id, { 0xCC });
	dead_byte.isjmpcall = false;
	dead_byte.has_relative = false;

	instruction = function->instructions.insert(instruction, dead_byte);
	instruction = function->instructions.insert(instruction, jmp_over);
	instruction += 2;

	return true;
}

bool obfuscator::add_junk(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	//This has a weird bug. Going to fix
	
	/*
	instruction_t jz{}; jz.load(function->func_id, { 0x74, 0x3 });
	instruction_t jnz{}; jnz.load(function->func_id, { 0x75, 0x1 });
	instruction_t garbage{}; garbage.load(function->func_id, { 0xE8 });
	instruction_t nop{}; nop.load(function->func_id, { 0x90 });
	garbage.zyinstr = nop.zyinstr;
	garbage.has_relative = false;
	garbage.isjmpcall = false;

	instruction = function->instructions.insert(instruction, jz);
	instruction = function->instructions.insert(instruction + 1, jnz);
	instruction = function->instructions.insert(instruction + 1, garbage);

	(instruction - 2)->relative.target_func_id = function->func_id;
	(instruction - 1)->relative.target_func_id = function->func_id;

	(instruction - 2)->relative.target_inst_id = (instruction + 1)->inst_id;
	(instruction - 1)->relative.target_inst_id = (instruction + 1)->inst_id;
	
	instruction++;
	*/
	return true;

}