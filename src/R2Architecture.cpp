// SPDX-FileCopyrightText: 2019-2022 thestr4ng3r, pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "R2Architecture.h"
#include "R2LoadImage.h"
#include "R2Scope.h"
#include "R2TypeFactory.h"
#include "R2CommentDatabase.h"
#include "R2Utils.h"
#include "ArchMap.h"

#include <funcdata.hh>
#include <coreaction.hh>

#include <iostream>

using namespace ghidra;

#include "Dalvik.inc.cpp"

// maps radare2 calling conventions to proto model names, tried in order against the loaded cspec
static const std::map<std::string, std::vector<std::string>> cc_map = {
	{ "cdecl", { "__cdecl" } },
	{ "fastcall", { "__fastcall" } },
	{ "ms", { "__fastcall", "MSABI" } }, // MSABI covers the x86-64 gcc cspec, which has no __fastcall
	{ "stdcall", { "__stdcall" } },
	{ "cdecl-thiscall-ms", { "__thiscall" } },
	{ "sh32", { "__stdcall" } },
	{ "amd64", { "__stdcall" } },
	{ "arm64", { "__cdecl" } },
	{ "arm32", { "__stdcall" } },
	{ "arm16", { "__stdcall" } }, /* not actually __stdcall */
	{ "ppc-32", { "__stdcall" } }, /* PPC cspec default_proto: r3-r10 GPR / f1-f13 FP */
	{ "ppc-64", { "__stdcall" } }
};

static bool isFloatReg(RAnal *anal, const char *name) {
	RRegItem *item = r_reg_get (anal->reg, name, -1);
	if (!item) {
		return false;
	}
	int type = item->type;
	r_unref (item);
	switch (type) {
	case R_REG_TYPE_FPU:
	case R_REG_TYPE_VEC64:
	case R_REG_TYPE_VEC128:
	case R_REG_TYPE_VEC256:
	case R_REG_TYPE_VEC512:
		return true;
	default:
		return false;
	}
}

static void childPentry(Element *parent, const VarnodeData *vn, bool flt) {
	auto pentry = child (parent, "pentry", {
		{ "minsize", "1" },
		{ "maxsize", std::to_string (vn->size) }
	});
	if (flt) {
		pentry->addAttribute ("storage", "float");
	}
	child (pentry, "addr", {
		{ "space", vn->space->getName () },
		{ "offset", hex (vn->offset) }
	});
}

std::string FilenameFromCore(RCore *core) {
	if (core && core->bin && core->bin->file) {
		return core->bin->file;
	}
	return std::string();
}

R2Architecture::R2Architecture(RCore *core, const std::string &sleigh_id)
	: SleighArchitecture (FilenameFromCore (core), sleigh_id.empty () ? SleighIdFromCore (core) : sleigh_id, &std::cout),
	coreMutex (core) {
#if 1
	collectSpecFiles(std::cerr);		///< Gather specification files in normal locations
	auto langs = getLanguageDescriptions ();
#endif
}

void R2Architecture::collectSpecFiles(std::ostream &errs) {
	SleighArchitecture::collectSpecFiles(errs);
}

const std::vector<LanguageDescription> &R2Architecture::getLanguageDescriptions() {
	return SleighArchitecture::getLanguageDescriptions();
}

ProtoModel *R2Architecture::protoModelFromR2CC(const char *cc) {
	auto it = cc_map.find (cc);
	if (it != cc_map.end ()) {
		for (const auto &name : it->second) {
			auto protoIt = protoModels.find (name);
			if (protoIt != protoModels.end ()) {
				return protoIt->second;
			}
		}
	}
	auto cached = r2CCModels.find (cc);
	if (cached != r2CCModels.end ()) {
		return cached->second;
	}
	ProtoModel *model = nullptr;
	{
		RCoreLock core (getCore ());
		const char *defcc = r_anal_cc_default (core->anal);
		if (defcc && !strcmp (defcc, cc)) {
			// the arch default cc is what the cspec default model describes, which is richer than the cc sdb
			model = defaultfp;
		}
	}
	if (!model) {
		try {
			model = buildProtoModelFromR2CC (cc);
		} catch (const LowlevelError &e) {
			addWarning ("Building a prototype model for calling convention " + std::string (cc) + " failed: " + e.explain);
		} catch (const DecoderError &e) {
			addWarning ("Building a prototype model for calling convention " + std::string (cc) + " failed: " + e.explain);
		}
	}
	r2CCModels[cc] = model;
	return model;
}

ProtoModel *R2Architecture::buildProtoModelFromR2CC(const char *cc) {
	RCoreLock core (getCore ());
	RAnal *anal = core->anal;
	if (!translate || !r_anal_cc_exist (anal, cc)) {
		return nullptr;
	}
	int maxargs = r_anal_cc_max_arg (anal, cc);
	const char *ret = r_anal_cc_ret (anal, cc, 0);
	if (!ret) {
		// a model without an output entry can throw ParamUnassignedError mid-decompile
		return nullptr;
	}
	int4 extrapop = defaultfp? defaultfp->getExtraPop (): 0;

	Document doc;
	doc.setName ("prototype");
	doc.addAttribute ("name", std::string ("r2:") + cc);
	doc.addAttribute ("extrapop", extrapop == ProtoModel::extrapop_unknown? "unknown": std::to_string (extrapop));

	auto input = child (&doc, "input");
	bool stackargs = false;
	std::vector<const VarnodeData *> gprargs, fltargs;
	for (int n = 0; n < maxargs && !stackargs; n++) {
		const char *loc = r_anal_cc_argloc (anal, cc, n, 0, 0);
		if (!loc || !strcmp (loc, "_")) {
			continue;
		}
		// {grouped} multi-register args are represented by their first register
		loc = r_anal_cc_location_first (anal, loc);
		if (!loc) {
			return nullptr;
		}
		if (*loc == '^') {
			stackargs = true;
			break;
		}
		const VarnodeData *vn = registerVarnodeFromR2Reg (loc);
		if (!vn) {
			return nullptr; // a model missing an arg slot would misnumber all later args
		}
		(isFloatReg (anal, loc)? fltargs: gprargs).push_back (vn);
	}
	// each storage class must form one contiguous pentry section; float goes first like the cspecs do
	for (const VarnodeData *vn : fltargs) {
		childPentry (input, vn, true);
	}
	for (const VarnodeData *vn : gprargs) {
		childPentry (input, vn, false);
	}
	const char *argn = r_anal_cc_argloc (anal, cc, maxargs, 0, 0);
	if (!stackargs && argn && argn[0] == '^' && argn[1] != '-') {
		stackargs = true;
	}
	if (stackargs) {
		// the cc sdb has no arg-save-area info, so stack args start right past any return address
		ut64 base = extrapop == ProtoModel::extrapop_unknown? 0: (ut64)extrapop;
		auto pentry = child (input, "pentry", {
			{ "minsize", "1" },
			{ "maxsize", "500" },
			{ "align", std::to_string (translate->getDefaultSize ()) }
		});
		child (pentry, "addr", { { "space", "stack" }, { "offset", hex (base) } });
	}
	auto output = child (&doc, "output");
	const char *rloc = r_anal_cc_location_first (anal, ret);
	const VarnodeData *retvn = rloc && *rloc != '^'? registerVarnodeFromR2Reg (rloc): nullptr;
	if (!retvn) {
		return nullptr;
	}
	childPentry (output, retvn, isFloatReg (anal, rloc));

	std::vector<std::pair<const VarnodeData *, bool>> effects;
	bool anyclobber = false;
	static const int regtypes[] = {
		R_REG_TYPE_GPR, R_REG_TYPE_FPU, R_REG_TYPE_VEC64,
		R_REG_TYPE_VEC128, R_REG_TYPE_VEC256, R_REG_TYPE_VEC512
	};
	for (int type : regtypes) {
		if (!anal->reg->regset[type].regs) {
			continue;
		}
		r_list_foreach_cpp<RRegItem>(anal->reg->regset[type].regs, [&](RRegItem *item) {
			const VarnodeData *vn = registerVarnodeFromR2Reg (item->name);
			if (!vn) {
				return;
			}
			for (const auto &e : effects) {
				if (e.first->space == vn->space && e.first->offset == vn->offset && e.first->size == vn->size) {
					return;
				}
			}
			bool clob = r_anal_cc_isclobber (anal, cc, item->name);
			anyclobber |= clob;
			effects.emplace_back (vn, clob);
		});
	}
	if (anyclobber) {
		// the sdb clobber/preserve sets are complements, so non-clobbered regs are unaffected
		auto killed = child (&doc, "killedbycall");
		auto unaffected = child (&doc, "unaffected");
		for (const auto &e : effects) {
			bool contained = false;
			for (const auto &o : effects) {
				if (&o != &e && o.first->space == e.first->space && o.first->size > e.first->size
						&& o.first->offset <= e.first->offset
						&& o.first->offset + o.first->size >= e.first->offset + e.first->size) {
					contained = true;
					break;
				}
			}
			if (contained) {
				continue; // subregisters ride with their container
			}
			child (e.second? killed: unaffected, "range", {
				{ "space", e.first->space->getName () },
				{ "first", hex (e.first->offset) },
				{ "last", hex (e.first->offset + e.first->size - 1) }
			});
		}
	}

	XmlDecode dec (this, &doc);
	return decodeProto (dec);
}

void R2Architecture::loadRegisters(const Translate *translate) {
	registers = {};
	if (!translate) {
		return;
	}
	std::map<VarnodeData, std::string> regs;
	translate->getAllRegisters (regs);
	for (const auto &reg : regs) {
		registers[reg.second] = reg.first;
		auto lower = tolower (reg.second);
		if (registers.find(lower) == registers.end()) {
			registers[lower] = reg.first;
		}
	}
}

const VarnodeData *R2Architecture::registerVarnodeFromR2Reg(const char *regname) {
	if (registers.empty ()) {
		// rebuilding here would invalidate every VarnodeData pointer handed out before
		loadRegisters (translate);
	}
	auto it = registers.find (regname);
	if (it == registers.end ()) {
		it = registers.find (tolower (regname));
	}
	return it == registers.end ()? nullptr: &it->second;
}

Address R2Architecture::registerAddressFromR2Reg(const char *regname) {
	const VarnodeData *vn = registerVarnodeFromR2Reg (regname);
	return vn? vn->getAddr (): Address (); // invalid addr if not found
}

std::string R2Architecture::registerNameFromAddress(const Address &addr, int4 size) {
	if (!translate || addr.isInvalid ()) {
		return "";
	}
	// r2 register profiles use lowercase names, sleigh uppercase
	return tolower (translate->getRegisterName (addr.getSpace (), addr.getOffset (), size));
}

Translate *R2Architecture::buildTranslator(DocumentStorage &store) {
	Translate *ret = SleighArchitecture::buildTranslator (store);
	loadRegisters(ret);
	return ret;
}

PcodeInjectLibrary *R2Architecture::buildPcodeInjectLibrary() {
	// Dalvik-only dynamic inject handling lives in Dalvik.inc.cpp; non-Dalvik payloads delegate normally.
	return buildR2DalvikPcodeInjectLibrary (this);
}

ContextDatabase *R2Architecture::getContextDatabase() {
	return context;
}

void R2Architecture::buildConstantPool(DocumentStorage &store) {
	cpool = buildR2DalvikConstantPool (this);
}

void R2Architecture::postSpecFile() {
	registerR2DalvikPostSpecInjects (this);
	RCoreLock core(getCore());
	r_list_foreach_cpp<RAnalFunction>(core->anal->fcns, [&](RAnalFunction *func) {
		if (func->is_noreturn) {
			// Configure noreturn functions
			Funcdata *infd = symboltab->getGlobalScope()->queryFunction(Address(getDefaultCodeSpace(), func->addr));
			if (!infd) {
				return;
			}
			infd->getFuncProto ().setNoReturn(true);
		}
	});
}

void R2Architecture::buildAction(DocumentStorage &store) {
	parseExtraRules (store); // Look for any additional rules
	allacts.universalAction (this);
	allacts.resetDefaults ();
	if (rawptr) {
		allacts.cloneGroup ("decompile", "decompile-deuglified");
		allacts.removeFromGroup ("decompile-deuglified", "fixateglobals"); // this action (ActionMapGlobals) will create these ugly uRam0x12345s
		allacts.setCurrent ("decompile-deuglified");
	}
}

void R2Architecture::buildLoader(DocumentStorage &store) {
	RCoreLock core (getCore ());
	collectSpecFiles (*errorstream);
	loader = new R2LoadImage (getCore (), this);
}

Scope *R2Architecture::buildDatabase(DocumentStorage &store) {
	symboltab = new Database (this, false);
	Scope *globalscope = new R2Scope (this);
	symboltab->attachScope (globalscope, nullptr);
	return globalscope;
}
void R2Architecture::buildCoreTypes(DocumentStorage &store) {
	// TODO: load from r2?
	types->setCoreType ("void", 1, TYPE_VOID, false);

	types->setCoreType ("bool", 1, TYPE_BOOL, false);
	types->setCoreType ("bool4", 4, TYPE_BOOL, false);
	types->setCoreType ("bool8", 8, TYPE_BOOL, false);

	types->setCoreType ("uint8_t", 1, TYPE_UINT, false);
	types->setCoreType ("uint16_t", 2, TYPE_UINT, false);
	types->setCoreType ("uint32_t", 4, TYPE_UINT, false);
	types->setCoreType ("uint64_t", 8, TYPE_UINT, false);
	types->setCoreType ("int8_t", 1, TYPE_INT, false);
	types->setCoreType ("int16_t", 2, TYPE_INT, false);
	types->setCoreType ("int32_t", 4, TYPE_INT, false);
	types->setCoreType ("int64_t", 8, TYPE_INT, false);
	types->setCoreType ("int", sizeof (int), TYPE_INT, false);

	types->setCoreType ("double", 8, TYPE_FLOAT, false);
	types->setCoreType ("float", 4, TYPE_FLOAT, false);
	types->setCoreType ("float8", 8, TYPE_FLOAT, false);
	types->setCoreType ("float10", 10, TYPE_FLOAT, false);
	types->setCoreType ("float16", 16 ,TYPE_FLOAT, false);

	types->setCoreType ("uchar", 1, TYPE_UNKNOWN, false);
	types->setCoreType ("ushort", 2, TYPE_UNKNOWN, false);
	types->setCoreType ("uint", 4, TYPE_UNKNOWN, false);
	types->setCoreType ("ulong", 8, TYPE_UNKNOWN, false);

	types->setCoreType ("code", 1, TYPE_CODE, false);

	types->setCoreType ("char", 1, TYPE_INT, true);
	types->setCoreType ("wchar", 2, TYPE_INT, true);
	// types->setCoreType ("char8_t", 1, TYPE_INT, true); // last type defined overrides the previous
	types->setCoreType ("char16_t", 2, TYPE_INT, true);
	types->setCoreType ("char32_t", 4, TYPE_INT, true);

	types->cacheCoreTypes ();
}

void R2Architecture::buildTypegrp(DocumentStorage &store) {
	r2TypeFactory_ = new R2TypeFactory (this);
	types = r2TypeFactory_;
}

void R2Architecture::buildCommentDB(DocumentStorage &store) {
	commentdb = new R2CommentDatabase (this);
}
