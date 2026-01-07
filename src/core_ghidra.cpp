/* r2ghidra - LGPL - Copyright 2019-2026 - thestr4ng3r, pancake */

#include "R2Architecture.h"
#include "CodeXMLParse.h"
#include "PrettyXmlEncode.h"
#include "R2PrintC.h"
#include "SleighAsm.h"
#include "ArchMap.h"
#include "PcodeFixupPreprocessor.h"
#include "r2ghidra.h"
#include <r_core.h>

// Windows clash
#ifdef restrict
#undef restrict
#endif

#include <libdecomp.hh>

#include <vector>
#include <mutex>

#undef DEBUG_EXCEPTIONS

#if R2_VERSION_NUMBER < 50909
extern "C" RCore *Gcore;
#endif

typedef bool (*ConfigVarCb)(void *user, void *data);

struct ConfigVar {
private:
	static std::vector<const ConfigVar *> vars_all;
	const std::string name;
	const char * const defval;
	const char * const desc;
	ConfigVarCb callback;
public:
	ConfigVar(const char *var, const char *defval, const char *desc, ConfigVarCb callback = nullptr)
		: name(std::string("r2ghidra") + "." + var), defval(defval), desc(desc), callback(callback) { vars_all.push_back(this); }

	const char *GetName() const { return name.c_str (); }
	const char *GetDefault () const { return defval; }
	const char *GetDesc() const { return desc; }
	ConfigVarCb GetCallback() const	{ return callback; }

	ut64 GetInt(RConfig *cfg) const	{ return r_config_get_i (cfg, name.c_str ()); }
	bool GetBool(RConfig *cfg) const { return GetInt (cfg) != 0; }
	std::string GetString(RConfig *cfg) const { return r_config_get (cfg, name.c_str ()); }
	void Set(RConfig *cfg, const char *s) const { r_config_set (cfg, name.c_str (), s); }
	static const std::vector<const ConfigVar *> &GetAll() { return vars_all; }
};

std::vector<const ConfigVar *> ConfigVar::vars_all;

bool SleighHomeConfig(void *user, void *data);

#define CV static const ConfigVar
CV cfg_var_sleighhome ("sleighhome",  "",         "SLEIGHHOME", SleighHomeConfig);
CV cfg_var_sleighid   ("lang",        "",         "Custom Sleigh ID to override auto-detection (e.g. x86:LE:32:default)");
CV cfg_var_anal       ("vars",        "true",     "Honor local variable / argument analysis from r2");
CV cfg_var_cmt_cpp    ("cmt.cpp",     "true",     "C++ comment style");
CV cfg_var_cmt_indent ("cmt.indent",  "4",        "Comment indent");
#if 0
CV cfg_var_nl_brace   ("nl.brace",    "false",    "Newline before opening '{'");
CV cfg_var_nl_else    ("nl.else",     "false",    "Newline before else");
#endif
CV cfg_var_indent     ("indent",      "4",        "Indent increment");
CV cfg_var_linelen    ("linelen",     "120",      "Max line length");
CV cfg_var_maximplref ("maximplref",  "2",        "Maximum number of references to an expression before showing an explicit variable.");
CV cfg_var_rawptr     ("rawptr",      "true",     "Show unknown globals as raw addresses instead of variables");
CV cfg_var_verbose    ("verbose",     "false",    "Show verbose warning messages while decompiling");
CV cfg_var_casts      ("casts",       "false",    "Show type casts where needed");
CV cfg_var_fixups     ("fixups",      "false",    "Apply pcode fixups");
CV cfg_var_roprop     ("roprop",      "0",        "Propagate read-only constants (0,1,2,3,4)");
CV cfg_var_timeout    ("timeout",     "0",        "Run decompilation in a separate process and kill it after a specific time");


static std::recursive_mutex decompiler_mutex;

class DecompilerLock {
private:
	RCore *_core;
public:
	DecompilerLock(RCore *core) : _core (core) {
		if (!decompiler_mutex.try_lock()) {
#if R2_VERSION_NUMBER >= 50909
			void *bed = r_cons_sleep_begin (_core->cons);
			decompiler_mutex.lock ();
			r_cons_sleep_end (_core->cons, bed);
#else
			void *bed = r_cons_sleep_begin ();
			decompiler_mutex.lock ();
			r_cons_sleep_end (bed);
#endif
		}
	}

	~DecompilerLock() {
		decompiler_mutex.unlock ();
	}
};

static const char* r2ghidra_help[] = {
	"Usage: " "pdg", "", "# Native Ghidra decompiler plugin",
	"pd:g", "[?]", "# Decompile current function with the Ghidra decompiler",
	"pd:g*", "", "# Decompiled code is returned to r2 as comment",
	"pd:ga", "", "# Side by side two column disasm and decompilation",
	"pd:gd", "", "# Dump the debug XML Dump",
	"pd:gj", "", "# Dump the current decompiled function as JSON",
	"pd:go", "", "# Decompile current function side by side with offsets",
	"pd:gp", "", "# Switch to RAsm and RAnal plugins driven by SLEIGH from Ghidra",
	"pd:gs", "", "# Display loaded Sleigh Languages (alias for pdgL)",
	"pd:gsd", " N", "# Disassemble N instructions with Sleigh and print pcode",
	"pd:gss", "", "# Display automatically matched Sleigh Language ID",
	"pd:gx", "", "# Dump the XML of the current decompiled function",
	"Environment:", "", "",
	"%SLEIGHHOME" , "", "# Path to ghidra sleigh directory (same as r2ghidra.sleighhome)",
	NULL
};
static void PrintUsage(const RCore *const core) {
#if R2_VERSION_NUMBER >= 50909
	r_cons_cmd_help (core->cons, r2ghidra_help, core->print->flags & R_PRINT_FLAGS_COLOR);
#else
	r_cons_cmd_help (r2ghidra_help, core->print->flags & R_PRINT_FLAGS_COLOR);
#endif
}

enum class DecompileMode {
	DEFAULT,
	XML,
	DEBUG_XML,
	OFFSET,
	STATEMENTS,
	DISASM,
	JSON
};

static void ApplyPrintCConfig(RConfig *cfg, PrintC *print_c) {
	if (!print_c) {
		return;
	}
	if (cfg_var_cmt_cpp.GetBool (cfg)) {
		print_c->setCPlusPlusStyleComments ();
	} else {
		print_c->setCStyleComments ();
	}
#if 0
	print_c->setSpaceAfterComma(true);
	print_c->setNewlineBeforeOpeningBrace(cfg_var_nl_brace.GetBool(cfg));
	print_c->setNewlineBeforeElse(cfg_var_nl_else.GetBool(cfg));
	print_c->setNewlineAfterPrototype(false);
#endif
	print_c->setIndentIncrement (cfg_var_indent.GetInt (cfg));
	print_c->setLineCommentIndent (cfg_var_cmt_indent.GetInt (cfg));
	print_c->setMaxLineSize (cfg_var_linelen.GetInt (cfg));
}

static void Decompile(RCore *core, ut64 addr, DecompileMode mode, std::stringstream &out_stream, RCodeMeta **out_code) {
	RAnalFunction *function = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	if (!function) {
		throw LowlevelError ("No function at this offset");
	}
	R2Architecture arch (core, cfg_var_sleighid.GetString (core->config));
	DocumentStorage store = DocumentStorage ();
	arch.max_implied_ref = cfg_var_maximplref.GetInt (core->config);
	arch.readonlypropagate = cfg_var_roprop.GetBool (core->config);
	arch.setRawPtr (cfg_var_rawptr.GetBool (core->config));
	arch.init (store);

	auto faddr = Address(arch.getDefaultCodeSpace (), function->addr);
	Funcdata *func = arch.symboltab->getGlobalScope ()->findFunction(faddr);
	arch.print->setOutputStream (&out_stream);
	arch.setPrintLanguage ("r2-c-language");
	auto r2c = dynamic_cast<R2PrintC *>(arch.print);
	bool showCasts = cfg_var_casts.GetBool (core->config);
	r2c->setOptionNoCasts (!showCasts);
	ApplyPrintCConfig (core->config, dynamic_cast<PrintC *>(arch.print));
	if (func == nullptr) {
		throw LowlevelError ("No function in Scope");
	}
	arch.getCore()->sleepBegin ();
	auto action = arch.allacts.getCurrent ();

	if (cfg_var_fixups.GetBool (core->config)) {
		PcodeFixupPreprocessor::fixupSharedReturnJumpToRelocs(function, func, core, arch);
	}

	int res;
#ifndef DEBUG_EXCEPTIONS
	try {
#endif
		action->reset (*func);
		res = action->perform (*func);
#ifndef DEBUG_EXCEPTIONS
	} catch (const LowlevelError &error) {
		arch.getCore()->sleepEndForce ();
		throw error;
	}
#endif
	arch.getCore()->sleepEnd ();
	if (res < 0) {
		R_LOG_WARN ("break");
	}
	if (cfg_var_verbose.GetBool (core->config)) {
		for (const auto &warning : arch.getWarnings()) {
			func->warningHeader("[r2ghidra] " + warning);
		}
	}
	switch (mode) {
	case DecompileMode::XML:
	case DecompileMode::DEFAULT:
	case DecompileMode::JSON:
	case DecompileMode::OFFSET:
	case DecompileMode::DISASM:
	case DecompileMode::STATEMENTS:
		arch.print->setMarkup(true);
		break;
	default:
		break;
	}
	if (mode == DecompileMode::XML) {
		out_stream << "<result><function>";
		{
		//func->encode (out_stream);
		//PrettyXmlEncode enc(out_stream);
		XmlEncode enc(out_stream);
		func->encode(enc, 0, true);
		}
		out_stream << "</function><code>";
	}
	switch (mode) {
	case DecompileMode::XML:
	case DecompileMode::DEFAULT:
	case DecompileMode::JSON:
	case DecompileMode::OFFSET:
	case DecompileMode::STATEMENTS:
	case DecompileMode::DISASM:
		// XXX: Can docFunction return unindented xml??
		arch.print->docFunction(func);
		if (mode != DecompileMode::XML) {
			*out_code = ParseCodeXML(func, out_stream.str().c_str ());
			if (!*out_code) {
				std::cout << out_stream.str().c_str () << std::endl;
				throw LowlevelError ("Failed to parse XML code from Decompiler");
			}
		}
		break;
	case DecompileMode::DEBUG_XML:
		{
		XmlEncode enc(out_stream);
		arch.encode(enc);
		}
		break;
	default:
		break;
	}
}

R_API RCodeMeta *r2ghidra_decompile_annotated_code(RCore *core, ut64 addr) {
	DecompilerLock lock(core);
	RCodeMeta *code = nullptr;
#ifndef DEBUG_EXCEPTIONS
	try {
#endif
		std::stringstream out_stream;
		Decompile (core, addr, DecompileMode::DEFAULT, out_stream, &code);
		return code;
#ifndef DEBUG_EXCEPTIONS
	} catch (const LowlevelError &error) {
		std::string s = "Ghidra Decompiler Error: " + error.explain;
 		code = r_codemeta_new (s.c_str ());
		// Push an annotation with: range = full string, type = error
		// For this, we have to modify RCodeMeta to have one more type; for errors
		return code;
	}
#endif
}

static void DecompileCmd (RCore *core, DecompileMode mode) {
	DecompilerLock lock(core);

#ifndef DEBUG_EXCEPTIONS
	try {
#endif
		RCodeMeta *code = nullptr;
		std::stringstream out_stream;
#if R2_VERSION_NUMBER >= 50909
		Decompile (core, core->addr, mode, out_stream, &code);
#else
		Decompile (core, core->offset, mode, out_stream, &code);
#endif
		switch (mode) {
		case DecompileMode::DISASM:
			{
#if defined(R2_ABIVERSION) && R2_ABIVERSION >= 40
				RVecCodeMetaOffset *offsets = r_codemeta_line_offsets (code);
#if R2_VERSION_NUMBER >= 50909
				char *s = r_codemeta_print_disasm (code, offsets, core->anal);
				r_cons_print (core->cons, s);
				free (s);
#else
				r_codemeta_print_disasm (code, offsets, core->anal);
#endif
				RVecCodeMetaOffset_free (offsets);
#else
				RVector *offsets = r_codemeta_line_offsets (code);
#if R2_VERSION_NUMBER >= 50909
				char *s = r_codemeta_print_disasm (code, offsets, core->anal);
				r_cons_print (core->cons, s);
				free (s);
#else
				r_codemeta_print_disasm (code, offsets, core->anal);
#endif
				r_vector_free (offsets);
#endif
			}
			break;
		case DecompileMode::OFFSET:
			{
#if defined(R2_ABIVERSION) && R2_ABIVERSION >= 40
				RVecCodeMetaOffset *offsets = r_codemeta_line_offsets (code);
#if R2_VERSION_NUMBER >= 60003
				char *s = r_codemeta_print2 (code, offsets, core->anal);
				r_cons_print (core->cons, s);
				free (s);
#elif R2_VERSION_NUMBER >= 50909
				char *s = r_codemeta_print (code, offsets);
				r_cons_print (core->cons, s);
				free (s);
#else
				r_codemeta_print (code, offsets);
				r_cons_flush ();
#endif
				RVecCodeMetaOffset_free (offsets);
#else
				RVector *offsets = r_codemeta_line_offsets (code);
#if R2_VERSION_NUMBER >= 60003
				char *s = r_codemeta_print2 (code, offsets, core->anal);
				r_cons_print (core->cons, s);
				free (s);
#elif R2_VERSION_NUMBER >= 50909
				char *s = r_codemeta_print (code, offsets);
				r_cons_print (core->cons, s);
				free (s);
#else
				r_codemeta_print (code, offsets);
				r_cons_flush ();
#endif
				r_vector_free (offsets);
#endif
			}
			break;
		case DecompileMode::DEFAULT:
			{
#if R2_VERSION_NUMBER >= 60003
				char *s = r_codemeta_print2 (code, nullptr, core->anal);
				r_cons_print (core->cons, s);
				free (s);
#elif R2_VERSION_NUMBER >= 50909
				char *s = r_codemeta_print (code, nullptr);
				r_cons_print (core->cons, s);
				free (s);
#else
				r_codemeta_print (code, nullptr);
#endif
			}
			break;
		case DecompileMode::STATEMENTS:
#if R2_VERSION_NUMBER >= 50909
			{
				char *s = r_codemeta_print_comment_cmds (code);
				r_cons_print (core->cons, s);
				free (s);
			}
#else
			r_codemeta_print_comment_cmds (code);
#endif
			break;
		case DecompileMode::JSON:
			{
#if R2_VERSION_NUMBER >= 50909
				char *s = r_codemeta_print_json (code);
				r_cons_println (core->cons, s);
				free (s);
#else
				r_codemeta_print_json (code);
#endif
			}
			break;
		case DecompileMode::XML:
			out_stream << "</code></result>";
			// fallthrough
		default:
#if R2_VERSION_NUMBER >= 50909
			r_cons_printf (core->cons, "%s\n", out_stream.str().c_str ());
#else
			r_cons_printf ("%s\n", out_stream.str().c_str ());
#endif
			break;
		}
		r_codemeta_free (code);
#ifndef DEBUG_EXCEPTIONS
	} catch (const LowlevelError &error) {
		std::string s = "Ghidra Decompiler Error: " + error.explain;
		if (mode == DecompileMode::JSON) {
			PJ *pj = pj_new ();
			if (pj) {
				pj_o (pj);
				pj_k (pj, "errors");
				pj_a (pj);
				pj_s (pj, s.c_str ());
				pj_end (pj);
				pj_end (pj);
#if R2_VERSION_NUMBER >= 50909
				r_cons_printf (core->cons, "%s\n", pj_string (pj));
#else
				r_cons_printf ("%s\n", pj_string (pj));
#endif
				pj_free (pj);
			}
		} else {
			R_LOG_WARN ("%s", s.c_str ());
		}
	}
#endif
}

// see sleighexample.cc
class AssemblyRaw : public AssemblyEmit {
public:
	void dump(const Address &addr, const string &mnem, const string &body) override {
		std::stringstream ss;
		addr.printRaw (ss);
		ss << ": " << mnem << ' ' << body;
#if R2_VERSION_NUMBER >= 50909
		r_cons_gprintf ("%s\n", ss.str().c_str ());
#else
		r_cons_printf ("%s\n", ss.str().c_str ());
#endif
	}
};

class PcodeRawOut : public PcodeEmit {
private:
	const Translate *trans = nullptr;

	void print_vardata(ostream &s, VarnodeData &data) {
		AddrSpace *space = data.space;
		if (space->getName() == "register" || space->getName() == "mem") {
			s << space->getTrans()->getRegisterName(data.space, data.offset, data.size);
		} else if (space->getName() == "ram") {
			switch (data.size) {
			case 1: s << "byte_ptr("; break;
			case 2: s << "word_ptr("; break;
			case 4: s << "dword_ptr("; break;
			case 8: s << "qword_ptr("; break;
			}
			space->printRaw(s, data.offset);
			s << ')';
		} else if (space->getName() == "const") {
			static_cast<ConstantSpace *>(space)->printRaw(s, data.offset);
		} else if (space->getName() == "unique") {
			s << '(' << data.space->getName() << ',';
			data.space->printOffset(s, data.offset);
			s << ',' << dec << data.size << ')';
		} else if (space->getName() == "DATA") {
			s << '(' << data.space->getName() << ',';
			data.space->printOffset(s,data.offset);
			s << ',' << dec << data.size << ')';
		} else {
			s << '(' << data.space->getName() << ',';
			data.space->printOffset(s, data.offset);
			s << ',' << dec << data.size << ')';
		}
	}

public:
	PcodeRawOut(const Translate *t): trans(t) {}

	void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) override {
		std::stringstream ss;
		if (opc == CPUI_STORE && isize == 3) {
			print_vardata (ss, vars[2]);
			ss << " = ";
			isize = 2;
		}
		if (outvar) {
			print_vardata (ss,*outvar);
			ss << " = ";
		}
		ss << get_opname(opc);
		// Possibly check for a code reference or a space reference
		ss << ' ';
		// For indirect case in SleighBuilder::dump(OpTpl *op)'s "vn->isDynamic(*walker)" branch.
		if (isize > 1 && vars[0].size == sizeof(AddrSpace *) && vars[0].space->getName() == "const"
				&& (vars[0].offset >> 24) == ((uintb)vars[1].space >> 24) && trans == ((AddrSpace*)vars[0].offset)->getTrans())
		{
			ss << ((AddrSpace*)vars[0].offset)->getName();
			ss << '[';
			print_vardata (ss, vars[1]);
			ss << ']';
			for (int4 i = 2; i < isize; i++) {
				ss << ", ";
				print_vardata (ss, vars[i]);
			}
		} else {
			print_vardata (ss, vars[0]);
			for (int4 i = 1; i < isize; i++) {
				ss << ", ";
				print_vardata (ss, vars[i]);
			}
		}
#if R2_VERSION_NUMBER >= 50909
		r_cons_gprintf ("    %s\n", ss.str().c_str ());
#else
		r_cons_printf ("    %s\n", ss.str().c_str ());
#endif
	}
};

static void Disassemble(RCore *core, ut64 ops) {
	if (!ops) {
		ops = 10; // random default value
	}
	R2Architecture arch (core, cfg_var_sleighid.GetString (core->config));
	DocumentStorage store;
	arch.init (store);

	const Translate *trans = arch.translate;
	PcodeRawOut emit (arch.translate);
	AssemblyRaw assememit;

#if R2_VERSION_NUMBER >= 50909
	Address addr (trans->getDefaultCodeSpace(), core->addr);
#else
	Address addr (trans->getDefaultCodeSpace(), core->offset);
#endif
	for (ut64 i = 0; i < ops; i++) {
		try {
			trans->printAssembly (assememit, addr);
			auto length = trans->oneInstruction (emit, addr);
			addr = addr + length;
		} catch (const BadDataError &error) {
			std::stringstream ss;
			addr.printRaw (ss);
			R_LOG_ERROR ("%s: invalid", ss.str ().c_str ());
			addr = addr + trans->getAlignment();
		}
	}
}

static void SetInitialSleighHome(RConfig *cfg) {
	if (!cfg_var_sleighhome.GetString (cfg).empty()) {
		return;
	}
	try {
		std::string path = SleighAsm::getSleighHome (cfg);
		cfg_var_sleighhome.Set (cfg, path.c_str ());
	} catch (LowlevelError &err) {
		// eprintf ("Cannot find sleigh in the default path\n");
	}
}

static void ListSleighLangs(RCore *core) {
	DecompilerLock lock(core);
	R2Architecture::collectSpecFiles (std::cerr);
	auto langs = R2Architecture::getLanguageDescriptions ();
	if (langs.empty()) {
		R_LOG_ERROR ("No languages available, make sure %s is set correctly!", cfg_var_sleighhome.GetName ());
		return;
	}
	std::vector<std::string> ids;
	std::transform (langs.begin(), langs.end (), std::back_inserter(ids), [](const LanguageDescription &lang) {
		return lang.getId ();
	});
	std::sort (ids.begin (), ids.end ());
	std::for_each (ids.begin (), ids.end (), [core](const std::string &id) {
#if R2_VERSION_NUMBER >= 50909
		r_cons_printf (core->cons, "%s\n", id.c_str ());
#else
		r_cons_printf ("%s\n", id.c_str ());
#endif
	});
}

static void PrintAutoSleighLang(RCore *core) {
	DecompilerLock lock (core);
	try {
		auto id = SleighIdFromCore (core);
#if R2_VERSION_NUMBER >= 50909
		r_cons_printf (core->cons, "%s\n", id.c_str ());
#else
		r_cons_printf ("%s\n", id.c_str ());
#endif
	} catch (LowlevelError &e) {
		R_LOG_WARN ("%s", e.explain.c_str ());
	}
}

static void EnablePlugin(RCore *core) {
	auto id = SleighIdFromCore (core);
	r_config_set (core->config, "r2ghidra.lang", id.c_str ());
	r_config_set (core->config, "asm.cpu", id.c_str ());
	r_config_set (core->config, "asm.arch", "r2ghidra");
	r_config_set (core->config, "anal.arch", "r2ghidra");
}

static void runcmd(RCore *core, const char *input) {
	switch (*input) {
	case 'd': // "pdgd"
		DecompileCmd (core, DecompileMode::DEBUG_XML);
		break;
	case '\0': // "pdg"
		DecompileCmd (core, DecompileMode::DEFAULT);
		break;
	case 'x': // "pdgx"
		DecompileCmd (core, DecompileMode::XML);
		break;
	case 'j': // "pdgj"
		DecompileCmd (core, DecompileMode::JSON);
		break;
	case 'o': // "pdgo"
		DecompileCmd (core, DecompileMode::OFFSET);
		break;
	case '*': // "pdg*"
		DecompileCmd (core, DecompileMode::STATEMENTS);
		break;
	case 'L': // "pdgL"
	case 's': // "pdgs"
		switch (input[1]) {
		case 's': // "pdgss"
			PrintAutoSleighLang (core);
			break;
		case 'd': // "pdgsd"
			Disassemble (core, r_num_math (core->num, input + 2));
			break;
		default:
			ListSleighLangs (core);
			break;
		}
		break;
	case 'a': // "pdga"
		DecompileCmd (core, DecompileMode::DISASM);
		break;
	case 'p': // "pdgp"
		EnablePlugin (core);
		break;
	default:
		PrintUsage (core);
		break;
	}
}

static void _cmd(RCore *core, const char *input) {
	int timeout = r_config_get_i (core->config, "r2ghidra.timeout");
	if (timeout > 0) {
#if __UNIX__
		// TODO: note that first execution is slower than the rest. and forking loses the cache
		int fds[2];
		if (pipe (fds) != 0) {
			R_LOG_ERROR ("Cannot pipe");
			return;
		}
		pid_t pid = r_sys_fork ();
		if (pid < 0) {
			R_LOG_ERROR ("Cannot fork");
			return;
		}
		if (pid == 0) {
			runcmd (core, input);
#if R2_VERSION_NUMBER >= 50909
			r_cons_flush (core->cons);
#else
			r_cons_flush ();
#endif
			fflush (stdout);
			write (fds[1], "\x12", 1);
			exit (0);
		} else {
			fd_set rfds;
			struct timeval tv;
			tv.tv_sec = timeout / 1000;
			tv.tv_usec = (timeout - (tv.tv_sec * 1000)) * 1000;
			FD_ZERO (&rfds);
			FD_SET (fds[0], &rfds);
			if (select (fds[0] + 1, &rfds, NULL, NULL, &tv) > 0) {
				char ch = 0;
				int rr = read (fds[0], &ch, 1);
				if (rr > 0 && ch == 0x12) {
					// eprintf ("Completed\n");
					// return;
				}
			} else {
				eprintf ("Timeout\n");
				kill (pid, 9);
			}
			fflush (stderr);
			fflush (stdout);
		}
		close (fds[0]);
		close (fds[1]);
#else
		R_LOG_WARN ("r2ghidra.timeout is not supported outside UNIX systems.");
		runcmd (core, input);
#endif
	} else {
		runcmd (core, input);
	}
}

#if R2_VERSION_NUMBER >= 50909
extern "C" bool r2ghidra_core_cmd(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	if (!strcmp (input, "pd:?")) {
		r_core_cmd_help_match (core, r2ghidra_help, (char*)"pd:g");
		return false;
	}
	if (r_str_startswith (input, "pd:g")) {
		_cmd (core, input + strlen ("pd:g"));
		return true;
	}
	// TODO: deprecate at some point
	if (r_str_startswith (input, "pdg")) {
		_cmd (core, input + strlen ("pdg"));
		return true;
	}
	return false;
}
#else
extern "C" int r2ghidra_core_cmd(void *user, const char *input) {
	RCore *core = (RCore *) user;
	if (r_str_startswith (input, "pdg")) {
		_cmd (core, input + 3);
		return true;
	}
	return false;
}
#endif

bool SleighHomeConfig(void */* user */, void *data) {
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	RConfigNode *node = reinterpret_cast<RConfigNode *>(data);
	SleighArchitecture::shutdown ();
	SleighArchitecture::specpaths = FileManage ();
	if (R_STR_ISNOTEMPTY (node->value)) {
		SleighArchitecture::scanForSleighDirectories (node->value);
	}
	return true;
}

extern "C" RArchPlugin r_arch_plugin_ghidra;

#if R2_VERSION_NUMBER >= 50909
extern "C" bool r2ghidra_core_init(RCorePluginSession *cps) {
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	startDecompilerLibrary (nullptr);
	RCore *core = reinterpret_cast<RCore *>(cps->core);
	r_arch_plugin_add (core->anal->arch, &r_arch_plugin_ghidra);
	RConfig *cfg = core->config;
	r_config_lock (cfg, false);
	for (const auto var : ConfigVar::GetAll ()) {
		RConfigNode *node = var->GetCallback()
			? r_config_set_cb (cfg, var->GetName (), var->GetDefault (), var->GetCallback ())
			: r_config_set (cfg, var->GetName (), var->GetDefault ());
		r_config_node_desc (node, var->GetDesc ());
	}
	r_config_lock (cfg, true);
	SetInitialSleighHome (cfg);
	return true;
}
#else
extern "C" int r2ghidra_core_init(void *user, const char *cmd) {
	std::lock_guard<std::recursive_mutex> lock(decompiler_mutex);
	startDecompilerLibrary (nullptr);
	RCmd *rcmd = reinterpret_cast<RCmd *>(user);
	RCore *core = reinterpret_cast<RCore *>(rcmd->data);
	Gcore = core;
	r_arch_plugin_add (core->anal->arch, &r_arch_plugin_ghidra);
	RConfig *cfg = core->config;
	r_config_lock (cfg, false);
	for (const auto var : ConfigVar::GetAll ()) {
		RConfigNode *node = var->GetCallback()
			? r_config_set_cb (cfg, var->GetName (), var->GetDefault (), var->GetCallback ())
			: r_config_set (cfg, var->GetName (), var->GetDefault ());
		r_config_node_desc (node, var->GetDesc ());
	}
	r_config_lock (cfg, true);
	SetInitialSleighHome (cfg);
	return true;
}
#endif

#if R2_VERSION_NUMBER >= 50909
extern "C" bool r2ghidra_core_fini(RCorePluginSession *cps, const char *cmd) {
	std::lock_guard<std::recursive_mutex> lock (decompiler_mutex);
	shutdownDecompilerLibrary ();
	return true;
}
#else
extern "C" int r2ghidra_core_fini(void *user, const char *cmd) {
	std::lock_guard<std::recursive_mutex> lock (decompiler_mutex);
	shutdownDecompilerLibrary ();
	return true;
}
#endif
