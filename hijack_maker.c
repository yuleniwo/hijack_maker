/*
 author: yuleniwo
*/
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

typedef struct 
{
	int* names_ord;
	unsigned* funcs_ord;
	unsigned* funcs_rva;
	unsigned* names_rva;
	char** names;
	unsigned count;
} exp_tab_t;

static const char* src1 = "#include <windows.h>\n"
"\n"
"typedef void (__stdcall *libfunc_t)(void);\n"
"\n"
"#define API_MAP(XX) \\\n";

static const char* src2 = "#define GEN_VAR(API) static libfunc_t lf ## API = NULL;\n"
"API_MAP(GEN_VAR)\n"
"#undef GEN_VAR\n"
"\n"
"#define GEN_FUNC(API) void __stdcall _ ## API(void) { \\\n"
"	lf ## API(); \\\n"
"}\n"
"API_MAP(GEN_FUNC)\n"
"#undef GEN_FUNC\n"
"\n"
"HMODULE load_dll(const char* file)\n"
"{\n"
"	char path[32768], buf[MAX_PATH];\n"
"	DWORD dw;\n"
"	HMODULE ret = NULL;\n"
"\n"
"	dw = GetSystemDirectoryA(path, sizeof(path));\n"
"	path[dw++] = ';';\n"
"\n"
"	dw += GetWindowsDirectoryA(path + dw, sizeof(path) - dw);\n"
"	path[dw++] = ';';\n"
"\n"
"	GetEnvironmentVariableA(\"PATH\", path + dw, sizeof(path) - dw);\n"
"\n"
"	dw = SearchPathA(path, file, \".dll\", sizeof(buf), buf, NULL);\n"
"	if(dw > 0 && dw < (DWORD)sizeof(buf))\n"
"		ret = LoadLibraryA(buf);\n"
"\n"
"	return ret;\n"
"}\n"
"\n"
"void load_api_addr(HMODULE h)\n"
"{\n"
"#define GET_API(API) lf ## API = (libfunc_t)GetProcAddress(h, (LPCSTR)#API);\n"
"	API_MAP(GET_API)\n"
"#undef GET_API\n"
"}\n"
"\n"
"void hook()\n"
"{\n"
"	\n"
"}\n"
"\n"
"BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)\n"
"{\n"
"	static HMODULE hdll;\n"
"	static const char* file = \"%s\";\n" /* placeholder: dll_file */
"	switch (dwReason)\n"
"	{\n"
"	case DLL_PROCESS_ATTACH:\n"
"		//DisableThreadLibraryCalls(hModule);\n"
"		hdll = load_dll(file);\n"
"		if(NULL == hdll)\n"
"		{\n"
"			char msg[256];\n"
"			wsprintfA(msg, \"Can not load file '%%s'!\", file);\n"
"			MessageBoxA(NULL, msg, \"Load error\", MB_ICONERROR);\n"
"			return FALSE;\n"
"		}\n"
"		load_api_addr(hdll);\n"
"		hook();\n"
"		return TRUE;\n"
"\n"
"	case DLL_PROCESS_DETACH:\n"
"		FreeLibrary(hdll);\n"
"		return TRUE;\n"
"	}\n"
"\n"
"	return TRUE;\n"
"}\n";

static const char* vcproj = 
"<?xml version=\"1.0\" encoding=\"gb2312\"?>\n"
"<VisualStudioProject ProjectType=\"Visual C++\" Version=\"8.00\" Keyword=\"Win32Proj\"\n"
"	Name=\"%s\" RootNamespace=\"%s\">\n" /* placeholder: proj proj */
"	<Platforms><Platform Name=\"Win32\"/><Platform Name=\"x64\"/></Platforms>\n"
"	<Configurations>\n"
"		<Configuration Name=\"Release|Win32\" OutputDirectory=\"$(SolutionDir)vc\\$(ProjectName)_$(PlatformName)_$(ConfigurationName)\"\n"
"			IntermediateDirectory=\"$(OutDir)\" ConfigurationType=\"2\" CharacterSet=\"1\"\n"
"			WholeProgramOptimization=\"1\">\n"
"			<Tool Name=\"VCCLCompilerTool\" RuntimeLibrary=\"0\" UsePrecompiledHeader=\"0\" WarningLevel=\"3\"\n"
"				PreprocessorDefinitions=\"WIN32;NDEBUG;_WINDOWS;_USRDLL;_WIN32_WINNT=0x0500\"\n"
"				Detect64BitPortabilityProblems=\"true\" DebugInformationFormat=\"3\"/>\n"
"			<Tool Name=\"VCLinkerTool\" LinkIncremental=\"1\" TargetMachine=\"1\" ModuleDefinitionFile=\"%s\"\n" /* placeholder: def_file */
"				GenerateDebugInformation=\"true\" SubSystem=\"2\" OptimizeReferences=\"2\" EnableCOMDATFolding=\"2\"/>\n"
"		</Configuration>\n"
"		<Configuration Name=\"Release|x64\" OutputDirectory=\"$(SolutionDir)vc\\$(ProjectName)_$(PlatformName)_$(ConfigurationName)\"\n"
"			IntermediateDirectory=\"$(OutDir)\" ConfigurationType=\"2\"\n"
"			CharacterSet=\"1\" WholeProgramOptimization=\"1\">\n"
"			<Tool Name=\"VCCLCompilerTool\" PreprocessorDefinitions=\"WIN32;NDEBUG;_WINDOWS;_USRDLL;_WIN32_WINNT=0x0500\"\n"
"				RuntimeLibrary=\"0\" UsePrecompiledHeader=\"0\" WarningLevel=\"3\" Detect64BitPortabilityProblems=\"true\"\n"
"				DebugInformationFormat=\"3\"/>\n"
"			<Tool Name=\"VCLinkerTool\" LinkIncremental=\"1\" SubSystem=\"2\" ModuleDefinitionFile=\"%s\"\n" /* placeholder: def_file */
"				GenerateDebugInformation=\"true\" OptimizeReferences=\"2\" EnableCOMDATFolding=\"2\" TargetMachine=\"17\"/>\n"
"		</Configuration>\n"
"	</Configurations>\n"
"	<Files>\n"
"		<Filter Name=\"src\" Filter=\"cpp;c;cc;cxx;def;odl;idl;hpj;bat;asm;asmx\">\n"
"			<File RelativePath=\".\\%s\"></File>\n" /* placeholder: c_file */
"		</Filter>\n"
"	</Files>\n"
"</VisualStudioProject>";

static const char* mingw_mk = 
".PHONY: clean cleanobj\n"
"\n"
"CC			:= gcc\n"
"LD			:= $(CC)\n"
"BITS		:= 32\n"
"PROJNAME	:= %s\n" /* placeholder: proj */
"TOP_DIR		:= $(PWD)\n"
"DEF_FILE	:= ./%s\n" /* placeholder: def_file */
"CFLAGS		:= -D NDEBUG -Wall -O2 -Wno-unused -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64\n"
"LDFLAGS		:= -static-libgcc -Wl,--enable-stdcall-fixup\n"
"\n"
"ifneq ($(BITS),64)\n"
"	BITS	:= 32\n"
"	CFLAGS += -m32\n"
"	LDFLAGS += -m32\n"
"else\n"
"	CFLAGS += -m64\n"
"	LDFLAGS += -m64\n"
"endif\n"
"\n"
"OBJ_DIR	:= $(TOP_DIR)/mingw/$(PROJNAME)_obj$(BITS)\n"
"BIN_DIR	:= $(TOP_DIR)/mingw/$(PROJNAME)_bin$(BITS)\n"
"LIBOUT	:= $(BIN_DIR)/$(PROJNAME).dll\n"
"\n"
"C_SRCS		:= %s\n" /* placeholder: c_file */
"C_OBJS		:= $(C_SRCS:%%.c=$(OBJ_DIR)/%%.o)\n"
"C_DEPS		:= $(C_OBJS:%%.o=%%.d)\n"
"\n"
"all: CHECKDIR $(C_OBJS) $(LIBOUT)\n"
"	@echo done.\n"
"\n"
"CHECKDIR:\n"
"	@mkdir -p $(OBJ_DIR) $(BIN_DIR)\n"
"\n"
"-include $(C_DEPS)\n"
"$(C_OBJS):$(OBJ_DIR)/%%.o:%%.c\n"
"	$(CC) -c $(CFLAGS) $(CFLAGS_EX) -Wp,-MMD,\"$(@:%%.o=%%.d)\" -MT\"$@\" -o $@ $<\n"
"\n"
"$(LIBOUT): $(C_OBJS)\n"
"	@echo \"---- Build : $@ ----\"\n"
"	$(LD) -shared -fPIC -Wl,--out-implib=$(@:%%.dll=%%.lib) $^ $(LDFLAGS) $(DEF_FILE) -o $@\n"
"	\n"
"clean:\n"
"	rm -f $(OBJ_DIR)/*.o\n"
"	rm -f $(OBJ_DIR)/*.d\n"
"	rm -f $(LIBOUT)\n"
"\n"
"cleanobj:\n"
"	rm -f $(OBJ_DIR)/*.o\n"
"	rm -f $(OBJ_DIR)/*.d\n";

static const char *file_basename(const char *name)
{
	const char *p = strchr(name, 0);
	while (p > name && p[-1] != '/' && p[-1] != '\\')
		--p;
	return (char*)p;
}

static void exp_tab_init(exp_tab_t* et)
{
	memset(et, 0, sizeof(exp_tab_t));
}

static void exp_tab_uninit(exp_tab_t* et)
{
	int i;

	if(et->names != NULL)
	{
		for(i=0; i<et->count; i++)
			free(et->names[i]);
		free(et->names);
		et->names = NULL;
	}

	free(et->funcs_rva);
	free(et->names_rva);
	free(et->names_ord);
	free(et->funcs_ord);
	et->funcs_rva = NULL;
	et->names_rva = NULL;
	et->names_ord = NULL;
	et->funcs_ord = NULL;
	et->count = 0;
}

static int exp_tab_alloc(exp_tab_t* et, unsigned count)
{
	int ret = 0;
	et->count = 0;
	et->funcs_rva = (unsigned*)malloc(count * sizeof(unsigned));
	et->names_rva = (unsigned*)malloc(count * sizeof(unsigned));
	et->names = (char**)malloc(count * sizeof(char*));
	et->names_ord = (int*)malloc(count * sizeof(int));
	et->funcs_ord = (unsigned*)malloc(count * sizeof(unsigned));
	if(NULL != et->funcs_rva || NULL != et->names_rva || 
		NULL != et->names || NULL != et->names_ord)
	{
		et->count = count;
		memset(et->funcs_rva, 0, count * sizeof(unsigned));
		memset(et->names_rva, 0, count * sizeof(unsigned));
		memset(et->names, 0, count * sizeof(char*));
		memset(et->names_ord, 0xff, count * sizeof(int));
		memset(et->funcs_ord, 0, count * sizeof(unsigned));
	}
	else
	{
		free(et->funcs_rva);
		free(et->names_rva);
		free(et->names);
		free(et->names_ord);
		free(et->funcs_ord);
		et->funcs_rva = NULL;
		et->names_rva = NULL;
		et->names = NULL;
		et->names_ord = NULL;
		et->funcs_ord = NULL;
		ret = -1;
	}

	return ret;
}

static int read_size(FILE *fp, int offset, void *buffer, int len)
{
	int r;

	r = fseek(fp, offset, SEEK_SET);

	if(0 == r)
		r = (fread(buffer, 1, len, fp) == len ? 0 : -1);
	else r = -1;

	return r;
}

static int find_end(const char* s, int len)
{
	int ret = 0;

	while(len-- > 0)
	{
		if(!*s++)
		{
			ret = 1;
			break;
		}
	}

	return ret;
}

static char* read_name(FILE *fp, int offset)
{
	char *ret = NULL, *prev = NULL;
	int r, cap = 32, pos = 0;
	r = fseek(fp, offset, SEEK_SET);
	if(0 == r)
	{
		do
		{
			ret = realloc(prev, cap);
			if(NULL == ret)
			{
				free(prev);
				break;
			}

			r = (int)fread(ret+pos, 1, cap-pos, fp);

			if(find_end(ret+pos, r))
			{
				if('\0' == ret[0])
				{
					free(ret);
					ret = NULL;
				}
				break;
			}
			else if(r < cap-pos)
			{
				free(ret);
				ret = NULL;
			}

			pos += r;
			cap <<= 1;
			prev = ret;
		} while (1);
	}

	return ret;
}

static const char* sec_attr(DWORD Characteristics)
{
	const char* ret = "N/A";
	Characteristics &= IMAGE_SCN_CNT_CODE | 
		IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;
	
	switch(Characteristics)
	{
	case IMAGE_SCN_CNT_CODE: ret = "C"; break;
	case IMAGE_SCN_CNT_INITIALIZED_DATA: ret = "ID"; break;
	case IMAGE_SCN_CNT_UNINITIALIZED_DATA: ret = "UD"; break;
	case (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA): ret = "C|ID"; break;
	case (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_UNINITIALIZED_DATA): ret = "C|UD"; break;
	case (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA): ret = "C|ID|UD"; break;
	case (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA): ret = "ID|UD"; break;
	}

	return ret;
}

static int check_func_rva(IMAGE_SECTION_HEADER* sec_hdrs, int count, unsigned rva)
{
	int i, ret = 1;

	for(i=0; i<count; i++)
	{
		if(rva >= sec_hdrs[i].VirtualAddress && 
			rva < sec_hdrs[i].VirtualAddress + sec_hdrs[i].SizeOfRawData)
		{
			if((sec_hdrs[i].Characteristics & IMAGE_SCN_CNT_CODE) == 
					IMAGE_SCN_CNT_CODE)
				ret = 0;
			break;
		}
	}

	return ret;
}

static int ana_exp_tab(FILE *fp, exp_tab_t* et)
{
	IMAGE_DOS_HEADER dos_hdr;
	IMAGE_FILE_HEADER file_hdr;
	IMAGE_OPTIONAL_HEADER32 opt_hdr32;
	IMAGE_OPTIONAL_HEADER64 opt_hdr64;
	IMAGE_SECTION_HEADER _sechdrs[8], *sec_hdrs, *sec_hdr = NULL;
	IMAGE_EXPORT_DIRECTORY exp_dir;
	DWORD sig, exp_addr, ref, j;
	int i, file_hdr_pos, opt_hdr_pos, sec_hdr_pos, sec_hdr_size;
	unsigned* names_rva = NULL;
	unsigned short* names_ord = NULL;
	const char* err = NULL;

	sec_hdrs = _sechdrs;
	if(read_size(fp, 0, &dos_hdr, (int)sizeof(dos_hdr)) || 
		dos_hdr.e_magic != IMAGE_DOS_SIGNATURE)
	{
		err = "Invalid image dos header!";
		goto lbl_end;
	}

	if(read_size(fp, dos_hdr.e_lfanew, &sig, (int)sizeof(sig)) || 
		sig != IMAGE_NT_SIGNATURE)
	{
		err = "Invalid NT file header!";
		goto lbl_end;
	}

	file_hdr_pos = dos_hdr.e_lfanew + (int)sizeof(sig);
	if(read_size(fp, file_hdr_pos, &file_hdr, (int)sizeof(file_hdr)))
	{
		err = "Read image file header failed!";
		goto lbl_end;
	}

	opt_hdr_pos = file_hdr_pos + (int)sizeof(file_hdr);
	if(IMAGE_FILE_MACHINE_I386 == file_hdr.Machine)
	{
		sec_hdr_pos = opt_hdr_pos + sizeof(opt_hdr32);
		if(read_size(fp, opt_hdr_pos, &opt_hdr32, sizeof(opt_hdr32)))
		{
			err = "Read optional header failed!";
			goto lbl_end;
		}

		if(IMAGE_DIRECTORY_ENTRY_EXPORT >= opt_hdr32.NumberOfRvaAndSizes)
		{
			err = "IMAGE_DIRECTORY_ENTRY_EXPORT not found!";
			goto lbl_end;
		}

		exp_addr = opt_hdr32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else if(IMAGE_FILE_MACHINE_AMD64 == file_hdr.Machine)
	{
		sec_hdr_pos = opt_hdr_pos + sizeof(opt_hdr64);
		if (read_size(fp, opt_hdr_pos, &opt_hdr64, sizeof(opt_hdr64)))
		{
			err = "Read optional header failed!";
			goto lbl_end;
		}

		if (IMAGE_DIRECTORY_ENTRY_EXPORT >= opt_hdr64.NumberOfRvaAndSizes)
		{
			err = "IMAGE_DIRECTORY_ENTRY_EXPORT not found!";
			goto lbl_end;
		}

		exp_addr = opt_hdr64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else
	{
		err = "Invalid file header machine code!";
		goto lbl_end;
	}

	sec_hdr_size = file_hdr.NumberOfSections * (int)sizeof(IMAGE_SECTION_HEADER);
	if(sec_hdr_size > (int)sizeof(_sechdrs))
	{
		sec_hdrs = (IMAGE_SECTION_HEADER*)malloc(sec_hdr_size);
		if(NULL == sec_hdrs)
		{
			err = "Can not alloc memory!";
			goto lbl_end;
		}
	}

	if(read_size(fp, sec_hdr_pos, sec_hdrs, sec_hdr_size))
	{
		err = "Read image section header failed!";
		goto lbl_end;
	}

	printf("VirtualAddress\tSizeOfRawData\tATTR\tName\n");
	for(i=0; i<file_hdr.NumberOfSections; i++)
	{
		char secname[IMAGE_SIZEOF_SHORT_NAME + 1];

		memcpy(secname, sec_hdrs[i].Name, IMAGE_SIZEOF_SHORT_NAME);
		secname[IMAGE_SIZEOF_SHORT_NAME] = '\0';
		printf("%08X\t%08X\t%s\t%s\n", sec_hdrs[i].VirtualAddress, 
			sec_hdrs[i].SizeOfRawData, sec_attr(sec_hdrs[i].Characteristics), 
			secname);

		if (NULL == sec_hdr && exp_addr >= sec_hdrs[i].VirtualAddress && 
			exp_addr < sec_hdrs[i].VirtualAddress + sec_hdrs[i].SizeOfRawData)
			sec_hdr = &sec_hdrs[i];
	}
	putchar('\n');

	if(sec_hdr != NULL)
		goto lbl_found;

	err = "Can not found EXPORT DIRECTORY data!";
	goto lbl_end;

lbl_found:
	ref = sec_hdr->VirtualAddress - sec_hdr->PointerToRawData;
	if (read_size(fp, exp_addr - ref, &exp_dir, sizeof(exp_dir)))
	{
		err = "Read export directory failed!";
		goto lbl_end;
	}

	if(exp_dir.NumberOfNames > exp_dir.NumberOfFunctions)
	{
		err = "Invalid export directory!";
		goto lbl_end;
	}
	if(exp_dir.NumberOfFunctions > 999999)
	{
		err = "Too many export functions!\n";
		goto lbl_end;
	}

	names_ord = (unsigned short*)malloc(sizeof(unsigned short) * exp_dir.NumberOfNames);
	names_rva = (unsigned*)malloc(sizeof(unsigned) * exp_dir.NumberOfNames);
	if(NULL == names_ord || NULL == names_rva)
	{
		err = "Can not alloc memory for exp tab!";
		goto lbl_end;
	}

	if(exp_tab_alloc(et, exp_dir.NumberOfFunctions))
	{
		err = "Can not alloc memory for exp tab!";
		goto lbl_end;
	}

	if(read_size(fp, exp_dir.AddressOfFunctions - ref, et->funcs_rva, et->count * sizeof(unsigned)))
	{
		err = "Read functions address failed!";
		goto lbl_end;
	}

	if(read_size(fp, exp_dir.AddressOfNames - ref, names_rva, exp_dir.NumberOfNames * sizeof(unsigned)))
	{
		err = "Read function names address failed!";
		goto lbl_end;
	}

	if(read_size(fp, exp_dir.AddressOfNameOrdinals - ref, names_ord, exp_dir.NumberOfNames * sizeof(unsigned short)))
	{
		err = "Read functions ordinal failed!";
		goto lbl_end;
	}

	for(j=0; j<exp_dir.NumberOfNames; j++)
	{
		i = names_ord[j];
		if(i >= exp_dir.NumberOfFunctions)
		{
			err = "Invalid name ordinal!";
			goto lbl_end;
		}
		et->names_ord[i] = (unsigned short)i;
		et->names_rva[i] = names_rva[j];
		et->names[i] = read_name(fp, names_rva[j] - ref);
	}

	for(j=0; j<exp_dir.NumberOfFunctions; j++)
	{
		et->funcs_ord[j] = exp_dir.Base + j;
		if(et->funcs_rva[j] != 0 && check_func_rva(sec_hdrs, 
			file_hdr.NumberOfSections, et->funcs_rva[j]))
		{
			printf("ord:%u, rva:%08X, name:%s not in code section!\n",
				et->funcs_ord[j], et->funcs_rva[j], 
				et->names[j] != NULL ? et->names[j] : "N/A");
		}
	}
	printf("\nNumberOfFunctions:%u, NumberOfNames:%u\n", exp_dir.NumberOfFunctions, exp_dir.NumberOfNames);

lbl_end:
	if(sec_hdrs != _sechdrs)
		free(sec_hdrs);
	
	free(names_ord);
	free(names_rva);

	if(err)
		fprintf(stderr, "%s\n", err);

	return NULL == err ? 0 : -1;
}

static void mk_name(const char* file, char* out, int maxlen, const char* ext)
{
	int i = 0;

	maxlen -= 8;
	for(; i<maxlen && file[i] != '\0' && file[i] != '.'; i++)
		out[i] = file[i];
	strcpy(&out[i], ext);
}

static int gen(const exp_tab_t* et, const char* file, 
	const char* c_file, const char* def_file, const char* vcproj_file,
	const char* make_file)
{
	FILE *fpc = NULL, *fpd = NULL, *fpp = NULL, *fpm = NULL;
	char proj[256];
	unsigned j;
	
	struct
	{
		FILE** fp;
		const char** file;
		const char* ext;
		char tmp[256];
	} prms[] = {
		{&fpc, &c_file, ".c"},
		{&fpd, &def_file, ".def"},
		{&fpp, &vcproj_file, ".vcproj"},
		{&fpm, &make_file, ".mak"},
	};

	file = file_basename(file);
	mk_name(file, proj, (int)sizeof(proj), "");
	
	for(j=0; j<sizeof(prms)/sizeof(prms[0]); j++)
	{
		if(NULL == *prms[j].file)
		{
			*prms[j].file = prms[j].tmp;
			mk_name(file, prms[j].tmp, (int)sizeof(prms[j].tmp), prms[j].ext);
		}
		
		*prms[j].fp = fopen(*prms[j].file, "w");
		if(NULL == *prms[j].fp)
		{
			fprintf(stderr, "Can not create file: %s\n", *prms[j].file);
			goto lbl_end;
		}
	}

	fprintf(fpc, src1);
	fprintf(fpd, "LIBRARY %s\n\nEXPORTS\n", file);
	for(j=0; j<et->count; j++)
	{
		if(0 == et->funcs_rva[j])
			continue;
		
		if(et->names[j] != NULL)
		{
			fprintf(fpc, "\tXX(%s) \\\n", et->names[j]);
			fprintf(fpd, "\t%s=_%s @%u\n", et->names[j], et->names[j], et->funcs_ord[j]);
		}
		else
		{
			fprintf(fpc, "\tXX(%u) \\\n", et->funcs_ord[j]);
			fprintf(fpd, "\t_%u @%u NONAME\n", et->funcs_ord[j], et->funcs_ord[j]);
		}
	}
	fprintf(fpc, "\n\n");
	fprintf(fpc, src2, file);
	
	// gen vcpkg file & mingw makefile
	fprintf(fpp, vcproj, proj, proj, def_file, def_file, c_file, c_file);
	fprintf(fpm, mingw_mk, proj, def_file, c_file);
	
lbl_end:
	if(fpc != NULL)
		fclose(fpc);
	if(fpd != NULL)
		fclose(fpd);
	if(fpp != NULL)
		fclose(fpp);
	if(fpm != NULL)
		fclose(fpm);
	return 0;
}

int main(int argc, char **argv)
{
	const char *file = NULL, *c_file = NULL, *def_file = NULL;
	const char *vcproj_file = NULL, *make_file = NULL;
	FILE* fp;
	exp_tab_t et;
	int i, j;
	char buf[MAX_PATH];
	DWORD dw;
	struct
	{
		char ch;
		const char** prm;
	} prms[] = {
		{'c', &c_file},
		{'d', &def_file},
		{'p', &vcproj_file},
		{'m', &make_file},
	};

	if(argc < 2)
	{
		fprintf(stderr, "-- Author: yuleniwo --\n");
		fprintf(stderr, "Usage: hijack_maker <dll_file_path.dll> [OPTIONS]\n"
			"Options:\n"
			"\t-c\toutput c source file name.\n"
			"\t-d\toutput .def file name.\n"
			"\t-p\toutput .vcproj file name.\n"
			"\t-m\toutput mingw makefile name.\n\n");
		return 1;
	}

	for(i=1; i<argc; i++)
	{
		if(argv[i][0] != '-' || '\0' == argv[i][1] || argv[i][2] != '\0')
		{
			file = argv[i];
			continue;
		}
		for(j=0; j<sizeof(prms)/sizeof(prms[0]); j++)
		{
			if(prms[j].ch == argv[i][1])
			{
				if(i + 1 < argc)
					*prms[j].prm = argv[i + 1];
				i++;
				break;
			}
		}
	}

	if(NULL == file)
		return 1;

	exp_tab_init(&et);
	fp = fopen(file, "rb");
	if(fp != NULL)
	{
lbl_retry:
		if(ana_exp_tab(fp, &et) == 0)
		{
			int i;
			char sord[16], sname[16];
			printf("fun_ord\tfun_rva\t\tnm_ord\tnm_rva\t\tname\n");
			for(i=0; i<et.count; i++)
			{
				if(0 == et.funcs_rva[i])
					continue;
				sprintf(sord, "%d", et.names_ord[i]);
				sprintf(sname, "%08X", et.names_rva[i]);
				printf("%u\t%08X\t%s\t%s\t%s\n", et.funcs_ord[i], 
					et.funcs_rva[i], 
					et.names_ord[i] >= 0 ? sord : "N/A", 
					et.names_rva[i] != 0 ? sname : "N/A\t", 
					et.names[i] != NULL ? et.names[i] : "N/A");
			}
			gen(&et, file, c_file, def_file, vcproj_file, make_file);
		}
	}
	else if(file[0] != '\0' && file[1] != ':')
	{
		dw = SearchPathA(NULL, file, ".dll", (DWORD)sizeof(buf), buf, NULL);
		if(dw > 0 && dw < MAX_PATH)
		{
			file = buf;
			fp = fopen(file, "rb");
			if(fp != NULL)
				goto lbl_retry;
		}
	}
	exp_tab_uninit(&et);

	if(fp != NULL)
		fclose(fp);
	else
		printf("Can not open file: %s\n", file);

	return 0;
}