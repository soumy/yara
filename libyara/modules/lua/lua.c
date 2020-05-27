
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <yara/mem.h>
#include <yara/modules.h>

#include <stdio.h>
#include <stdlib.h>

//We support lua version 5.3 and above
#if LUA_VERSION_NUM >= 503

#define MODULE_NAME lua

typedef struct ScanData
{
	lua_State* lstate;
	unsigned char* luabuffer;
	size_t luabuffersize;
}SCAN_DATA, *P_SCAN_DATA;

define_function(run_lua)
{
	int retval = 0;
	YR_SCAN_CONTEXT* context = scan_context();
	YR_MEMORY_BLOCK* block = first_memory_block(context);
	YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;
	YR_OBJECT* module_object = module();
	P_SCAN_DATA pScanData = NULL;
	lua_State* l = NULL;
	char* func_name = string_argument(1);

	if (module_object->data != NULL)
	{
		pScanData = module_object->data;
		l = pScanData->lstate;

	}

	if (l != NULL)
	{
		foreach_memory_block(iterator, block)
		{
			unsigned char* block_data = block->fetch_data(block);

			if(block_data == NULL)
				continue;

			int err = (luaL_loadbuffer(l, pScanData->luabuffer, pScanData->luabuffersize, "code")
				|| lua_pcall(l, 0, 0, 0));
			if (err != LUA_OK)
			{
#ifdef _DEBUG
				fprintf(stderr, "Invalid lua script\n");
#endif
				break;
			}
			lua_getglobal(l, func_name);
			lua_pushlstring(l, block_data, block->size); //TODO: make this zerocopy later
			lua_pcall(l, 1, 1, 0);
			retval = lua_tonumber(l, -1);
			lua_pop(l, 1);
			if (retval)
				break;
		}
	}
	return_integer(retval);
}

begin_declarations;
declare_function("execute", "s", "i", run_lua);
end_declarations;

int module_initialize(
	YR_MODULE* module)
{
	return ERROR_SUCCESS;
}


int module_finalize(
	YR_MODULE* module)
{
	return ERROR_SUCCESS;
}

int module_load(
	YR_SCAN_CONTEXT* context,
	YR_OBJECT* module_object,
	void* module_data,
	size_t module_data_size)
{
	if (module_data == NULL)
		return ERROR_SUCCESS;

	P_SCAN_DATA pScanData = (P_SCAN_DATA)malloc(sizeof(SCAN_DATA));
	FAIL_ON_ERROR(!pScanData);
	memset(pScanData, 0, sizeof(SCAN_DATA));
	pScanData->luabuffer = module_data;
	pScanData->luabuffersize = module_data_size;
	lua_State* l = luaL_newstate();
	luaL_openlibs(l);
	//Add current directory to the loader search paths
	luaL_dostring(l, "package.path = package.path .. ';?.lua'");
	luaL_dostring(l, "package.cpath = package.cpath .. ';?.dll'");
	pScanData->lstate = l;
	FAIL_ON_ERROR((pScanData->lstate == NULL));
	module_object->data = pScanData;
	return ERROR_SUCCESS;
}


int module_unload(
	YR_OBJECT* module_object)
{
	if (module_object->data != NULL)
	{
		P_SCAN_DATA pScanData = module_object->data;
		if(pScanData->lstate != NULL)
			lua_close(pScanData->lstate);
		free(pScanData);
	}
	return ERROR_SUCCESS;
}

#endif