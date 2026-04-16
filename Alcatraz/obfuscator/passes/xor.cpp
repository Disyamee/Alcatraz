#include "../obfuscator.h"

// XOR a, b  →  push scratch; mov scratch, a; and scratch, b; or a, b; sub a, scratch; pop scratch
// (a | b) - (a & b) = a ^ b
bool obfuscator::obfuscate_xor(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	if (instruction->zyinstr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && instruction->zyinstr.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {

		if (instruction->zyinstr.operands[0].size < 32)
			return true;

		auto first_it = lookupmap.find(instruction->zyinstr.operands[0].reg.value);
		auto second_it = lookupmap.find(instruction->zyinstr.operands[1].reg.value);

		if (first_it == lookupmap.end() || second_it == lookupmap.end())
			return true;

		auto first = first_it->second;
		auto second = second_it->second;

		if (first == second)
			return true;

		if (first == x86::rsp || second == x86::rsp)
			return true;

		if (first.size() != second.size())
			return true;

		// Pick a scratch register that doesn't collide with first or second
		bool is32 = first.isGpd();
		x86::Gp scratch;
		x86::Gp scratch_push;

		if (first.id() != 0 && second.id() != 0) {
			scratch_push = x86::rax;
			if (is32) scratch = x86::eax; else scratch = x86::rax;
		} else if (first.id() != 1 && second.id() != 1) {
			scratch_push = x86::rcx;
			if (is32) scratch = x86::ecx; else scratch = x86::rcx;
		} else {
			scratch_push = x86::rdx;
			if (is32) scratch = x86::edx; else scratch = x86::rdx;
		}

		assm.push(scratch_push);
		assm.mov(scratch, first);
		assm.and_(scratch, second);
		assm.or_(first, second);
		assm.sub(first, scratch);
		assm.pop(scratch_push);

		void* fn = nullptr;
		auto err = rt.add(&fn, &code);

		auto jitinstructions = this->instructions_from_jit((uint8_t*)fn, code.codeSize());
		int orig_id = instruction->inst_id;
		instruction = function->instructions.erase(instruction);
		instruction -= 1;
		jitinstructions.at(0).inst_id = orig_id;
		for (auto jit : jitinstructions) {
			instruction = function->instructions.insert(instruction + 1, jit);
		}

		code.reset();
		code.init(rt.environment());
		code.attach(&this->assm);
	}

	return true;
}
