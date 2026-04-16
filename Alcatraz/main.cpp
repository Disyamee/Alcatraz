#include "pe/pe.h"
#include "pdbparser/pdbparser.h"
#include "obfuscator/obfuscator.h"

#include <iostream>
#include <filesystem>
#include <algorithm>
#include <unordered_set>
#include <sstream>
#include <iomanip>

static bool has_sidecar_pdb(const std::string& binary_path) {
	std::filesystem::path pdb_path = binary_path;
	pdb_path.replace_extension(".pdb");
	return std::filesystem::exists(pdb_path);
}

static std::vector<obfuscator::input_function_t> convert_pdb_functions(const std::vector<pdbparser::sym_func>& pdb_functions) {
	std::vector<obfuscator::input_function_t> functions;
	functions.reserve(pdb_functions.size());

	for (const auto& f : pdb_functions) {
		obfuscator::input_function_t out{};
		out.id = f.id;
		out.offset = f.offset;
		out.name = f.name;
		out.size = f.size;
		out.obfuscate = f.obfuscate;
		out.ctfflattening = f.ctfflattening;
		out.movobf = f.movobf;
		out.mutateobf = f.mutateobf;
		out.leaobf = f.leaobf;
		out.antidisassembly = f.antidisassembly;
		out.iatobf = f.iatobf;
		out.stringenc = f.stringenc;
		out.callhideobf = f.callhideobf;
		out.bcfobf = f.bcfobf;
		functions.push_back(out);
	}

	return functions;
}

static std::vector<obfuscator::input_function_t> collect_functions_from_pdata(pe64& pe) {
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

	std::vector<obfuscator::input_function_t> functions;
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

		obfuscator::input_function_t func{};
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

	std::vector<obfuscator::input_function_t> normalized;
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

int main(int args, char* argv[]) {

	if (args != 2) {
		printf("Usage: [exe_path]\n");
		return 0;
	}


	std::string binary_path = argv[1];
	const clock_t begin_time = clock();

	try {
		srand(time(NULL));

		pe64 pe(binary_path);
		std::vector<obfuscator::input_function_t> functions;
		if (has_sidecar_pdb(binary_path)) {
			pdbparser pdb(&pe);
			functions = convert_pdb_functions(pdb.parse_functions());
			std::cout << "Using PDB symbols" << std::endl;
		}
		else {
			functions = collect_functions_from_pdata(pe);
			std::cout << "No PDB found, using .pdata runtime functions" << std::endl;
		}
		std::cout << "Successfully parsed " << functions.size() << " function(s)" << std::endl;

		uint32_t total_func_size = 0;
		for (auto& f : functions) {
			if (f.obfuscate && f.size >= 5)
				total_func_size += f.size;
		}
		uint32_t section_size = (total_func_size * 12) + 0x100000;
		if (section_size < 10000000)
			section_size = 10000000;

		auto new_section = pe.create_section(".vmp0", section_size, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE);

		obfuscator obf(&pe);
		obf.create_functions(functions);
		obf.run(new_section, true);

		auto extension = std::filesystem::path(binary_path).extension();
		pe.save_to_disk(std::filesystem::path(binary_path).replace_extension().string() + ".obf" + extension.string(), new_section, obf.get_added_size());
			

	}
	catch (std::runtime_error e)
	{
		std::cout << "Runtime error: " << e.what() << std::endl;
	}

	auto t_end = std::chrono::high_resolution_clock::now();
	std::cout << "Finished in " << float(clock() - begin_time) / CLOCKS_PER_SEC << " seconds" << std::endl;
	return getchar();
}
