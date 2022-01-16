
#include <rz_core.h>

#include <memory>

int main(int argc, const char *argv[]) {
	if (argc != 2 || !strcmp(argv[1], "-h")) {
		eprintf("usage: %s <filename>.frames\n", argv[0]);
		return 1;
	}
	std::unique_ptr<RzCore, decltype(&rz_core_free)> core(rz_core_new(), rz_core_free);
	RzCoreFile *cf = rz_core_file_open(core.get(), "hex://a942", RZ_PERM_RWX, 0);
	rz_core_bin_load(core.get(), NULL, 0);
	rz_config_set(core->config, "asm.arch", "6502");

	std::unique_ptr<RzReg, decltype(&rz_reg_free)> reg(rz_reg_new(), rz_reg_free);
	if (!reg) {
		eprintf("Failed to init reg.\n");
		return 1;
	}
	char *reg_profile = rz_analysis_get_reg_profile(core->analysis);
	if (!reg_profile) {
		eprintf("Failed to get reg profile.\n");
		return 1;
	}
	bool succ = rz_reg_set_profile_string(reg.get(), reg_profile);
	rz_mem_free(reg_profile);
	if (!succ) {
		eprintf("Failed to apply reg profile.\n");
		return 1;
	}
	std::unique_ptr<RzAnalysisILVM, decltype(&rz_analysis_il_vm_free)> vm(rz_analysis_il_vm_new(core->analysis, reg.get()), rz_analysis_il_vm_free);
	rz_analysis_il_vm_sync_to_reg(vm.get(), reg.get()); // initial sync to get any plugin-specified initialization

	RzAnalysisILStepResult sr = rz_analysis_il_vm_step(core->analysis, vm.get(), reg.get());
	if (sr != RZ_ANALYSIS_IL_STEP_RESULT_SUCCESS) {
		eprintf("Stepping failed.\n");
		return 1;
	}
	printf("%#x\n", (unsigned int)rz_reg_getv(reg.get(), "a"));

	return 0;
}
