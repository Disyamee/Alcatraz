#pragma once

#include "../../Alcatraz/pe/pe.h"
#include "../../Alcatraz/pdbparser/pdbparser.h"
#include "../../Alcatraz/obfuscator/obfuscator.h"

#include <atomic>
#include <mutex>
#include <string>

namespace inter {

	extern std::atomic<int>  g_obf_progress;
	extern std::atomic<int>  g_obf_total;
	extern std::atomic<bool> g_obf_running;
	extern std::atomic<bool> g_obf_done;
	extern std::string       g_obf_error;
	extern std::mutex        g_obf_mutex;

	std::vector<pdbparser::sym_func> load_context(std::string path);

	void run_obfuscator(std::vector<pdbparser::sym_func> funcs, bool obfuscate_entry_point);

};