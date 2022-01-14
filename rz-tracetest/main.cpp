
#include <rz_core.h>

int main(int argc, const char *argv[]) {
	RzCore *core = rz_core_new();
	rz_core_cmd0(core, "?E rz-tracetest");
	rz_cons_flush();
	rz_core_free(core);
	return 0;
}
