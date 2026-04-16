#include "interface.h"


#include <Windows.h>
#include <time.h>
#include <filesystem>
#include <algorithm>
#include <unordered_set>
#include <sstream>

static bool has_sidecar_pdb(const std::string& binary_path) {
	std::filesystem::path pdb_path = binary_path;
	pdb_path.replace_extension(".pdb");
	return std::filesystem::exists(pdb_path);
}

static std::vector<pdbparser::sym_func> collect_functions_from_pdata(pe64& pe) {
	auto nt = pe.get_nt();
	if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION)
		throw std::runtime_error("input binary doesn't expose exception metadata (.pdata)");

	const auto& exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (exception_dir.VirtualAddress == 0 || exception_dir.Size < sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY))
		throw std::runtime_error("input binary doesn't expose usable .pdata runtime function entries");

	auto text_section = pe.get_section(".text");
	if (!text_section)
		throw std::runtime_error("couldn't find .text section");

	const uint32_t text_begin = text_section->VirtualAddress;
	const uint32_t text_end = text_begin + (std::max)(text_section->Misc.VirtualSize, text_section->SizeOfRawData);

	const auto buffer_size = pe.get_buffer()->size();
	const uint64_t entries_rva = exception_dir.VirtualAddress;
	const uint64_t entries_size = exception_dir.Size;
	if (entries_rva + entries_size > buffer_size)
		throw std::runtime_error("invalid .pdata directory range");

	const auto* entries =
		reinterpret_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY*>(pe.get_buffer()->data() + exception_dir.VirtualAddress);
	const size_t entry_count = exception_dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

	std::vector<pdbparser::sym_func> functions;
	functions.reserve(entry_count);
	std::unordered_set<uint32_t> seen_offsets;
	int id = 0;

	for (size_t i = 0; i < entry_count; ++i) {
		const auto begin = entries[i].BeginAddress;
		const auto end = entries[i].EndAddress;

		if (begin >= end)
			continue;
		if (begin < text_begin || end > text_end)
			continue;

		const uint32_t offset = begin - text_begin;
		if (!seen_offsets.insert(offset).second)
			continue;

		pdbparser::sym_func func{};
		func.id = id++;
		func.offset = offset;
		func.size = end - begin;

		std::ostringstream name;
		name << "sub_" << std::uppercase << std::hex << begin;
		func.name = name.str();

		functions.push_back(func);
	}

	std::sort(functions.begin(), functions.end(), [](const auto& a, const auto& b) {
		return a.offset < b.offset;
	});

	std::vector<pdbparser::sym_func> normalized;
	normalized.reserve(functions.size());
	for (size_t i = 0; i < functions.size(); ++i) {
		auto f = functions[i];
		if (i + 1 < functions.size()) {
			const uint32_t next_offset = functions[i + 1].offset;
			if (f.offset < next_offset && f.offset + f.size > next_offset)
				f.size = next_offset - f.offset;
		}
		if (f.size >= 5)
			normalized.push_back(f);
	}

	return normalized;
}


std::string binary_path;
std::vector<pdbparser::sym_func> inter::load_context(std::string path) {

	//If user loads new image

	srand(time(NULL));
	binary_path = path;
	pe64 pe(path);
	if (has_sidecar_pdb(path)) {
		pdbparser pdb(&pe);
		return pdb.parse_functions();
	}
	return collect_functions_from_pdata(pe);
}

void inter::run_obfuscator(std::vector<pdbparser::sym_func> funcs, bool obfuscate_entry_point) {

	pe64 pe(binary_path);
	auto extension = std::filesystem::path(binary_path).extension();

	std::remove((std::filesystem::path(binary_path).replace_extension().string() + ".obf" + extension.string()).c_str());

	uint32_t total_func_size = 0;
	for (auto& f : funcs) {
		if (f.obfuscate && f.size >= 5)
			total_func_size += f.size;
	}
	// Obfuscation passes expand code ~10x (CFF, MOV, ADD, anti-disasm). Add 1MB minimum.
	uint32_t section_size = (total_func_size * 12) + 0x100000;
	if (section_size < 10000000)
		section_size = 10000000;

	auto new_section = pe.create_section(".vmp0", section_size, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE);

	std::vector<obfuscator::input_function_t> input_functions;
	input_functions.reserve(funcs.size());
	for (const auto& f : funcs) {
		obfuscator::input_function_t in{};
		in.id = f.id;
		in.offset = f.offset;
		in.name = f.name;
		in.size = f.size;
		in.obfuscate = f.obfuscate;
		in.ctfflattening = f.ctfflattening;
		in.movobf = f.movobf;
		in.mutateobf = f.mutateobf;
		in.leaobf = f.leaobf;
		in.antidisassembly = f.antidisassembly;
		in.iatobf = f.iatobf;
		in.stringenc = f.stringenc;
		in.callhideobf = f.callhideobf;
		in.bcfobf = f.bcfobf;
		input_functions.push_back(in);
	}

	obfuscator obf(&pe);
	obf.create_functions(input_functions);
	obf.run(new_section, obfuscate_entry_point);

	pe.save_to_disk(std::filesystem::path(binary_path).replace_extension().string() + ".obf" + extension.string(), new_section, obf.get_added_size());

}
