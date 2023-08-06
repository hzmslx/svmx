#include "pch.h"
#include "module.h"
#include "queue.h"

typedef struct ModuleEntry {
	void (*init)(void);
	QTAILQ_ENTRY(ModuleEntry) node;
	module_init_type type;
}ModuleEntry;

typedef QTAILQ_HEAD(, ModuleEntry) ModuleTypeList;

static ModuleTypeList init_type_list[MODULE_INIT_MAX];
static bool modules_init_done[MODULE_INIT_MAX];

static ModuleTypeList dso_init_list;


static void init_lists(void) {
	static int inited;
	int i;

	if (inited) {
		return;
	}

	for (i = 0; i < MODULE_INIT_MAX; i++) {
		QTAILQ_INIT(&init_type_list[i]);
	}

	QTAILQ_INIT(&dso_init_list);

	inited = 1;
}

static ModuleTypeList* find_type(module_init_type type) {
	init_lists();

	return &init_type_list[type];
}

void module_call_init(module_init_type type) {
	ModuleTypeList* l;
	ModuleEntry* e;

	if (modules_init_done[type]) {
		return;
	}

	l = find_type(type);


	QTAILQ_FOREACH(e, l, node) {
		e->init();
	}


	modules_init_done[type] = true;
}

