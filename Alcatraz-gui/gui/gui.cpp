#include "gui.h"
#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"

#include "../interface/interface.h"

#include <d3d11.h>
#include <tchar.h>
#include <filesystem>
#include <algorithm>
#include <fstream>

std::string path = "";

int panel = 0;
int selected_func = 0;
char func_name[1024];

std::vector<pdbparser::sym_func>funcs;
std::vector<pdbparser::sym_func>funcs_to_obfuscate;
std::vector<std::string>logs;
bool obf_entry_point;

bool global_cff = true;
bool global_movobf = true;
bool global_mutateobf = true;
bool global_leaobf = true;
bool global_antidisasm = true;
bool global_iatobf = true;
bool global_stringenc = true;

void gui::render_interface() {
	ImGuiStyle& style = ImGui::GetStyle();
	style.WindowPadding = ImVec2(0, 0);
	
	ImGui::SetNextWindowSize(ImVec2(1280, 800));
	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::Begin("Alcaztaz",0, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoScrollWithMouse);

	if (ImGui::BeginMenuBar()) {

		if (ImGui::BeginMenu("File")) {

			if (ImGui::MenuItem("Open")) {

				char filename[MAX_PATH];

				OPENFILENAMEA ofn;
				ZeroMemory(&filename, sizeof(filename));
				ZeroMemory(&ofn, sizeof(ofn));
				ofn.lStructSize = sizeof(ofn);
				ofn.hwndOwner = NULL; 
				ofn.lpstrFilter = "Executables\0*.exe\0Dynamic Link Libraries\0*.dll\0Drivers\0*.sys";
				ofn.lpstrFile = filename;
				ofn.nMaxFile = MAX_PATH;
				ofn.lpstrTitle = "Select your file.";
				ofn.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST;
				GetOpenFileNameA(&ofn);

				if (!std::filesystem::exists(filename)) {
					MessageBoxA(0, "Couldn't find file!", "Error", 0);
				}
				else {
					path = filename;
					try {
						funcs = inter::load_context(path);
						std::sort(funcs.begin(), funcs.end(), [](const pdbparser::sym_func& a, const pdbparser::sym_func& b) {
							return a.name < b.name;
						});
					}
					catch (std::runtime_error e)
					{
						MessageBoxA(0, e.what(), "Exception", 0);
						path = "";
					}
					selected_func = 0;
					funcs_to_obfuscate.clear();
					
				}

			}

			ImGui::EndMenu();
		}

		ImGui::EndMenuBar();
	}

	if (path.size()) {

		ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.12f, 0.12f, 0.94f));
		ImGui::BeginChild("selectionpanel", ImVec2(100, 800), true, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
		if (ImGui::Button("Protection", ImVec2(100, 100)))
			panel = 0;

		ImGui::EndChild();


		if (panel == 0) {
			ImGui::SetNextWindowPos(ImVec2(100, 25));

			ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.24f, 0.24f, 0.24f, 0.94f));
			if (ImGui::BeginChild("optionpanel", ImVec2(300, 775), true, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove )) {

			
				ImGui::SetNextItemWidth(300);
				ImGui::InputText("##treeAddFuncs", func_name, 1024);

				if (ImGui::TreeNode("Added functions")) {
					for (int i = 0; i < funcs_to_obfuscate.size(); i++)
					{
						if (ImGui::Button(funcs_to_obfuscate.at(i).name.c_str()))
							selected_func = funcs_to_obfuscate.at(i).id;

					}

					ImGui::TreePop();
				}

				if (ImGui::TreeNode("Functions")) {
					for (int i = 0; i < funcs.size(); i++)
					{
						if (funcs.at(i).size >= 5 && (funcs.at(i).name.find(func_name) != std::string::npos)) {
							if (ImGui::Button(funcs.at(i).name.c_str()))
								selected_func = funcs.at(i).id;
						}
					
					}

					ImGui::TreePop();
				}

				if (ImGui::TreeNode("Settings (all functions)")) {
					if (ImGui::Checkbox("Control flow flattening", &global_cff)) {
						for (auto& f : funcs_to_obfuscate) f.ctfflattening = global_cff;
						for (auto& f : funcs) f.ctfflattening = global_cff;
					}
					if (ImGui::Checkbox("Immediate MOV obfuscation", &global_movobf)) {
						for (auto& f : funcs_to_obfuscate) f.movobf = global_movobf;
						for (auto& f : funcs) f.movobf = global_movobf;
					}
					if (ImGui::Checkbox("Mutate", &global_mutateobf)) {
						for (auto& f : funcs_to_obfuscate) f.mutateobf = global_mutateobf;
						for (auto& f : funcs) f.mutateobf = global_mutateobf;
					}
					if (ImGui::Checkbox("LEA obfuscation", &global_leaobf)) {
						for (auto& f : funcs_to_obfuscate) f.leaobf = global_leaobf;
						for (auto& f : funcs) f.leaobf = global_leaobf;
					}
					if (ImGui::Checkbox("Anti disassembly", &global_antidisasm)) {
						for (auto& f : funcs_to_obfuscate) f.antidisassembly = global_antidisasm;
						for (auto& f : funcs) f.antidisassembly = global_antidisasm;
					}
					if (ImGui::Checkbox("IAT obfuscation", &global_iatobf)) {
						for (auto& f : funcs_to_obfuscate) f.iatobf = global_iatobf;
						for (auto& f : funcs) f.iatobf = global_iatobf;
					}
					if (ImGui::Checkbox("String encryption", &global_stringenc)) {
						for (auto& f : funcs_to_obfuscate) f.stringenc = global_stringenc;
						for (auto& f : funcs) f.stringenc = global_stringenc;
					}
					ImGui::Checkbox("Obfuscate entry point", &obf_entry_point);
					ImGui::TreePop();
				}


				if (ImGui::Button("Add all")) {

					while (funcs.size() != 0) {
						funcs_to_obfuscate.push_back(funcs.front());
						funcs.erase(funcs.begin());
					}

				}

				ImGui::SameLine();

				if (ImGui::Button("Remove all")) {

					while (funcs_to_obfuscate.size() != 0) {
						funcs.push_back(funcs_to_obfuscate.front());
						funcs_to_obfuscate.erase(funcs_to_obfuscate.begin());
					}
					std::sort(funcs.begin(), funcs.end(), [](const pdbparser::sym_func& a, const pdbparser::sym_func& b) {
						return a.name < b.name;
					});

				}

				if (ImGui::Button("Export functions")) {
					char filename[MAX_PATH];
					OPENFILENAMEA ofn;
					ZeroMemory(&filename, sizeof(filename));
					ZeroMemory(&ofn, sizeof(ofn));
					ofn.lStructSize = sizeof(ofn);
					ofn.hwndOwner = NULL;
					ofn.lpstrFilter = "Text Files\0*.txt\0All Files\0*.*\0";
					ofn.lpstrFile = filename;
					ofn.nMaxFile = MAX_PATH;
					ofn.lpstrTitle = "Export function names";
					ofn.lpstrDefExt = "txt";
					ofn.Flags = OFN_OVERWRITEPROMPT;
					if (GetSaveFileNameA(&ofn)) {
						std::ofstream out(filename);
						if (out) {
							for (auto& f : funcs)
								out << f.name << "\n";
							for (auto& f : funcs_to_obfuscate)
								out << f.name << "\n";
							out.close();
							MessageBoxA(0, "Functions exported.", "Success", 0);
						}
						else {
							MessageBoxA(0, "Couldn't write file!", "Error", 0);
						}
					}
				}

				if (ImGui::Button("Compile")) {
					try {
						inter::run_obfuscator(funcs_to_obfuscate, obf_entry_point);
						MessageBoxA(0, "Compiled", "Success", 0);
					}
					catch (std::runtime_error e)
					{
						MessageBoxA(0, e.what(), "Exception", 0);
						path = "";
						//std::cout << "Runtime error: " << e.what() << std::endl;
					}
				}
			}
			ImGui::EndChild();

			
			ImGui::SetNextWindowPos(ImVec2(400, 25));
			ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.48f, 0.48f, 0.48f, 0.94f));
			ImGui::BeginChild("functionpanel", ImVec2(880,775), true, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);


			
			auto already_added = std::find_if(funcs_to_obfuscate.begin(), funcs_to_obfuscate.end(), [&](const pdbparser::sym_func infunc) { return infunc.id == selected_func; });
			if (already_added != funcs_to_obfuscate.end()) {

				auto func = already_added;
				ImGui::Text("Name : %s", func->name.c_str());
				ImGui::Text("Address : %x", func->offset);
				ImGui::Text("Size : %i bytes", func->size);

				ImGui::Checkbox("Control flow flattening", &func->ctfflattening);
				ImGui::Checkbox("Immediate MOV obfuscation", &func->movobf);
				ImGui::Checkbox("Mutate", &func->mutateobf);
				ImGui::Checkbox("LEA obfuscation", &func->leaobf);
				ImGui::Checkbox("Anti disassembly", &func->antidisassembly);
				ImGui::Checkbox("IAT obfuscation", &func->iatobf);
				ImGui::Checkbox("String encryption", &func->stringenc);
			}
			else {

				auto func = std::find_if(funcs.begin(), funcs.end(), [&](const pdbparser::sym_func infunc) { return infunc.id == selected_func; });
				if (func != funcs.end()) {
					ImGui::Text("Name : %s", func->name.c_str());
					ImGui::Text("Address : %x", func->offset);
					ImGui::Text("Size : %i bytes", func->size);

					ImGui::Checkbox("Control flow flattening", &func->ctfflattening);
					ImGui::Checkbox("Immediate MOV obfuscation", &func->movobf);
					ImGui::Checkbox("Mutate", &func->mutateobf);
					ImGui::Checkbox("LEA obfuscation", &func->leaobf);
					ImGui::Checkbox("Anti disassembly", &func->antidisassembly);
					ImGui::Checkbox("IAT obfuscation", &func->iatobf);
					ImGui::Checkbox("String encryption", &func->stringenc);

					if (ImGui::Button("Add to list")) {

						if (std::find_if(funcs_to_obfuscate.begin(), funcs_to_obfuscate.end(), [&](const pdbparser::sym_func infunc) {return infunc.id == func->id; }) == funcs_to_obfuscate.end()) {
							funcs_to_obfuscate.push_back(*func);
							funcs.erase(func);
						}
					}
				}
			}
			
			ImGui::SetCursorPosY(700);
			ImGui::Text(path.c_str());

			ImGui::EndChild();

			ImGui::PopStyleColor();

			ImGui::PopStyleColor();

		}
		

		ImGui::PopStyleColor();

		
	}

	ImGui::End();

}
