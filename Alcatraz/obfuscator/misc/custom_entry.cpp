#include "../obfuscator.h"

// Disable optimization so LTCG cannot reorder custom_main / custom_main_end.
// Their addresses are used to compute the shellcode size — they MUST be adjacent.
#pragma optimize("", off)

__forceinline int _strcmp(const char* s1, const char* s2)
{
	while (*s1 && (*s1 == *s2))
	{
		s1++;
		s2++;
	}
	return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

__declspec(safebuffers) int obfuscator::custom_dll_main(HINSTANCE instance, DWORD fdwreason, LPVOID reserved) {

	return 0;
}
void obfuscator::custom_dll_main_end() {};


// Free function so we can take its address for byte-copy into the target PE (no member function pointer cast).
#pragma optimize("", off)
__declspec(safebuffers) static void custom_entry_code(void) {

	uint64_t peb = (uint64_t)__readgsqword(0x60);
	uint64_t base = *(uint64_t*)(peb + 0x10);
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

	// Find ".vmp0" by comparing bytes (no string literal — keeps code position-independent when copied into target)
	PIMAGE_SECTION_HEADER section = nullptr;
	PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
	WORD nsec = nt->FileHeader.NumberOfSections;
	for (WORD i = 0; i < nsec; i++) {
		const char* n = (const char*)first[i].Name;
		if (n[0] == '.' && n[1] == 'v' && n[2] == 'm' && n[3] == 'p' && n[4] == '0') {
			section = &first[i];
			break;
		}
	}
	if (!section)
		return;

	uint32_t real_entry = *(uint32_t*)(base + section->VirtualAddress);
	real_entry ^= (uint32_t)nt->OptionalHeader.SizeOfStackCommit;
	// Inline rotate-right to guarantee no out-of-stub calls.
	uint32_t rot = nt->FileHeader.TimeDateStamp & 31u;
	if (rot) {
		real_entry = (real_entry >> rot) | (real_entry << (32u - rot));
	}
	((void(*)(void))(base + real_entry))();
}
static void custom_entry_code_end(void) {}
#pragma optimize("", on)

const uint8_t* get_custom_entry_code(size_t* out_size) {
	*out_size = (size_t)((const uint8_t*)&custom_entry_code_end - (const uint8_t*)&custom_entry_code);
	return (const uint8_t*)&custom_entry_code;
}

__declspec(safebuffers) void obfuscator::custom_main() {
	custom_entry_code();
}
void obfuscator::custom_main_end() {}