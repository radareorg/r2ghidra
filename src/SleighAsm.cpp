/* r2ghidra - LGPL - Copyright 2020-2026 - FXTi, pancake */

#include "ArchMap.h"
#include "SleighAsm.h"

// define it here because sleighc needs to compile without anal_ghidra.cpp
extern "C" {
R_API RCore *Gcore = nullptr;
}

void SleighAsm::init(const char *cpu, int bits, bool bigendian, RIO *io, RConfig *cfg) {
	if (!io) {
		if (Gcore == nullptr) {
			throw LowlevelError ("Can't get RIO from RBin");
		}
		io = Gcore->io;
		cfg = Gcore->config;
	}
	if (description.empty()) {
		/* Initialize sleigh spec files */
		scanSleigh (getSleighHome (cfg));
		collectSpecfiles ();
	}
	std::string new_sleigh_id = SleighIdFromSleighAsmConfig (Gcore, cpu, bits, bigendian, description);
	if (!sleigh_id.empty() && sleigh_id == new_sleigh_id) {
		return;
	}
	initInner (io, new_sleigh_id);
}

void SleighAsm::initInner(RIO *io, std::string sleigh_id) {
	/* Initialize Sleigh */
	loader = std::move (AsmLoadImage (io));
	docstorage = std::move (DocumentStorage ());
	resolveArch (sleigh_id);
	buildSpecfile (docstorage);
	context = std::move(ContextInternal ());
	trans.reset (&loader, &context);
	trans.initialize (docstorage);
	parseProcConfig (docstorage);
	parseCompConfig (docstorage);
	alignment = trans.getAlignment ();
	RCore *core = (RCore *)io->coreb.core;
#if R2_VERSION_NUMBER >= 50909
	minopsz = ai (core, sleigh_id, R_ARCH_INFO_MINOP_SIZE);
	maxopsz = ai (core, sleigh_id, R_ARCH_INFO_MAXOP_SIZE);
#else
	minopsz = ai (core, sleigh_id, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	maxopsz = ai (core, sleigh_id, R_ANAL_ARCHINFO_MAX_OP_SIZE);
#endif
	trans.clearCache ();
	initRegMapping ();
	this->sleigh_id = sleigh_id;
}

static void parseProto(const Element *el, std::vector<std::string> &arg_names, std::vector<std::string> &ret_names) {
	if (el->getName() != "prototype") {
		throw LowlevelError ("Expecting <prototype> tag");
	}
	const List &list(el->getChildren());
	for (auto iter = list.begin(); iter != list.end (); iter++) {
		const Element *subnode = *iter;
		auto name = subnode->getName();
		if (name == "input" || name == "output") {
			const List &flist(subnode->getChildren());
			for (auto fiter = flist.begin(); fiter != flist.end (); ++fiter) {
				const Element *subel = *fiter;
				const Element *reg = *subel->getChildren().begin();
				if (subel->getName() == "pentry" && reg->getName() == "register") {
					int4 num = subel->getNumAttributes(), i = 0;
					for (; i < num; i++) {
						if (subel->getAttributeName(i) == "metatype" && subel->getAttributeValue(i) == "float") {
							break;
						}
					}
					if (i != num) {
						continue;
					}
					for (int p = 0; p < reg->getNumAttributes(); p++) {
						if (reg->getAttributeName (p) == "name") {
							if (subnode->getName () == "input") {
								arg_names.push_back (reg->getAttributeValue (p));
							} else {
								ret_names.push_back (reg->getAttributeValue (p));
							}
						}
					}
				}
			}
		}
	}
}

static void parseDefaultProto(const Element *el, std::vector<std::string> &arg_names, std::vector<std::string> &ret_names) {
	const List &list(el->getChildren());
	List::const_iterator iter;

	for (iter = list.begin (); iter != list.end (); iter++) {
		// Decompiler will parse the same entry, and exit if multiple exists.
		arg_names.clear ();
		ret_names.clear ();
		parseProto(*iter, arg_names, ret_names);
	}
}

void SleighAsm::parseCompConfig(DocumentStorage &store) {
	const Element *el = store.getTag ("compiler_spec");
	if (!el) {
		throw LowlevelError ("No compiler configuration tag found");
	}
	const List &list(el->getChildren ());
	List::const_iterator iter;

	for (iter = list.begin(); iter != list.end (); iter++) {
		const string &elname((*iter)->getName ());
		if (elname == "stackpointer") {
			sp_name = (*iter)->getAttributeValue ("register");
		} else if (elname == "default_proto") {
			parseDefaultProto(*iter, arg_names, ret_names);
		}
	}
}

static std::unordered_map<std::string, std::string> parseRegisterData(const Element *el) {
	const List &child_list(el->getChildren());
	List::const_iterator iter;

	std::unordered_map<std::string, std::string> reg_group;

	for (iter = child_list.begin(); iter != child_list.end (); iter++) {
		if ((*iter)->getName() != "register") {
			throw LowlevelError ("Unexpected node get from register_data in processor spec!");
		}
		const std::string &name = (*iter)->getAttributeValue("name");
		std::string group, hidden, unused, rename;
		try {
			group = (*iter)->getAttributeValue("group");
			hidden = (*iter)->getAttributeValue("hidden");
			unused = (*iter)->getAttributeValue("unused");
			rename = (*iter)->getAttributeValue("rename");
		} catch (const DecoderError &e) {
			std::string err_prefix("Unknown attribute: ");
			if (e.explain == err_prefix + "group") { /* nothing */ }
			else if (e.explain == err_prefix + "hidden") { /* nothing */ }
			else if (e.explain == err_prefix + "unused") { /* nothing */ }
			else if (e.explain == err_prefix + "rename") { /* nothing */ }
			else {
				throw;
			}
		}
		reg_group.insert ({name, group});
	}
	return reg_group;
}

/*
 * From architecture.cc's parseProcessorConfig()
 * This function is used to parse processor config.
 * It is stripped to only parse context_data.
 * Context data is used to fill contextreg.
 */
void SleighAsm::parseProcConfig(DocumentStorage &store) {
	const Element *el = store.getTag ("processor_spec");
	if (el == nullptr) {
		throw LowlevelError ("No processor configuration tag found");
	}
	XmlDecode decoder (&trans, el);
	uint4 elemId = decoder.openElement (ELEM_PROCESSOR_SPEC);
	for (;;) {
		uint4 subId = decoder.peekElement();
		if(subId == 0) {
			break;
		}
		if (subId == ELEM_PROGRAMCOUNTER) {
			decoder.openElement();
			pc_name = decoder.readString(ATTRIB_REGISTER);
			decoder.closeElement(subId);
		} else if (subId == ELEM_CONTEXT_DATA) {
			context.decodeFromSpec(decoder);
		} else if (subId == ELEM_REGISTER_DATA) {
			decoder.openElement();
			parseRegisterData(decoder.getCurrentXmlElement());
			decoder.closeElement(subId);
		} else {
			decoder.openElement();
			decoder.closeElementSkipping(subId);
		}
	}
	decoder.closeElement(elemId);
}

/*
 * From sleigh_arch.cc's buildSpecFile()
 * This function is used to fill DocumentStorage with sleigh files.
 */
void SleighAsm::buildSpecfile(DocumentStorage &store)
{
	const LanguageDescription &language(description[languageindex]);
	std::string compiler = sleigh_id.substr(sleigh_id.rfind(':') + 1);
	const CompilerTag &compilertag(language.getCompiler(compiler));

	std::string processorfile;
	std::string compilerfile;
	std::string slafile;

	specpaths.findFile(processorfile, language.getProcessorSpec());
	specpaths.findFile(compilerfile, compilertag.getSpec());
	specpaths.findFile(slafile, language.getSlaFile());

	try {
		Document *doc = store.openDocument(processorfile);
		store.registerTag(doc->getRoot());
	} catch (DecoderError &err) {
		ostringstream serr;
		serr << "XML error parsing processor specification: " << processorfile;
		serr << "\n " << err.explain;
		throw SleighError (serr.str());
	} catch (LowlevelError &err) {
		ostringstream serr;
		serr << "Error reading processor specification: " << processorfile;
		serr << "\n " << err.explain;
		throw SleighError (serr.str());
	}

	try {
		Document *doc = store.openDocument(compilerfile);
		store.registerTag(doc->getRoot());
	} catch (DecoderError &err) {
		ostringstream serr;
		serr << "XML error parsing compiler specification: " << compilerfile;
		serr << "\n " << err.explain;
		throw SleighError (serr.str());
	} catch (LowlevelError &err) {
		ostringstream serr;
		serr << "Error reading compiler specification: " << compilerfile;
		serr << "\n " << err.explain;
		throw SleighError (serr.str ());
	}
	istringstream s("<sleigh>" + slafile + "</sleigh>");
	try {
		Document *doc = store.parseDocument (s);
		store.registerTag (doc->getRoot());
	} catch (DecoderError &err) {
		ostringstream serr;
		serr << "XML error parsing SLEIGH file: " << slafile;
		serr << "\n " << err.explain;
		throw SleighError (serr.str());
	} catch (LowlevelError &err) {
		ostringstream serr;
		serr << "Error reading SLEIGH file: " << slafile;
		serr << "\n " << err.explain;
		throw SleighError (serr.str());
	}
}

/*
 * From sleigh_arch.cc's resolveArchitecture()
 * This function is used to reolve the index of asm.cpu in description.
 * It is stripped because asm.cpu is the result of normalizeArchitecture().
 */
void SleighAsm::resolveArch(const string &archid) {
	std::string baseid = archid.substr(0, archid.rfind(':'));
	languageindex = -1;
	for (size_t i = 0; i < description.size(); i++) {
		std::string id = description[i].getId();
		// std::string id = description[i].getProcessor();
		if (id == archid || id == baseid) {
			languageindex = i;
			if (description[i].isDeprecated()) {
				throw LowlevelError ("Language " + baseid + " is deprecated");
			}
			break;
		}
	}
	if (languageindex == -1) {
		throw LowlevelError ("No sleigh specification for " + baseid + " from " + archid);
	}
}

/*
 * From sleigh_arch.cc's scanForSleighDirectories()
 * This function is used to scan directories for SLEIGH specification files.
 */
void SleighAsm::scanSleigh(const string &rootpath) {
	specpaths = FileManage(); // Empty specpaths

	std::vector<std::string> ghidradir;
	std::vector<std::string> procdir;
	std::vector<std::string> procdir2;
	std::vector<std::string> languagesubdirs;

	// /Users/pancake/.local/share/radare2/plugins/r2ghidra_sleigh/
	FileManage::scanDirectoryRecursive(ghidradir, ".", rootpath, 2);
	FileManage::scanDirectoryRecursive(ghidradir, "Ghidra", rootpath, 2);
	size_t i;
	for (i = 0; i < ghidradir.size(); i++) {
		FileManage::scanDirectoryRecursive(procdir, "Processors", ghidradir[i],
		                                   1); // Look for Processors structure
		FileManage::scanDirectoryRecursive(procdir, "contrib", ghidradir[i], 1);
	}
	if (procdir.size() != 0) {
		for (i = 0; i < procdir.size(); i++) {
			FileManage::directoryList(procdir2, procdir[i]);
		}
		vector<string> datadirs;
		for (i = 0; i < procdir2.size(); i++) {
			FileManage::scanDirectoryRecursive(datadirs, "data", procdir2[i], 1);
		}
		vector<string> languagedirs;
		for (i = 0; i < datadirs.size(); i++) {
			FileManage::scanDirectoryRecursive(languagedirs, "languages", datadirs[i], 1);
		}
		for (i = 0; i < languagedirs.size(); i++) {
			languagesubdirs.push_back(languagedirs[i]);
		}
		// In the old version we have to go down one more level to get to the ldefs
		for (i = 0; i < languagedirs.size(); i++) {
			FileManage::directoryList(languagesubdirs, languagedirs[i]);
		}
	}
	// If we haven't matched this directory structure, just use the rootpath as the directory
	// containing the ldef
	if (languagesubdirs.size() == 0) {
		languagesubdirs.push_back(rootpath);
	}
	for (i = 0; i < languagesubdirs.size(); i++) {
		specpaths.addDir2Path(languagesubdirs[i]);
	}
}

/*
 * From sleigh_arch.cc's loadLanguageDescription()
 * This function is used to read a SLEIGH .ldefs file.
 */
void SleighAsm::loadLanguageDescription(const string &specfile) {
	ifstream s(specfile.c_str());
	if (!s) {
		throw LowlevelError("Unable to open: " + specfile);
	}
	XmlDecode decoder ((const AddrSpaceManager *)0);
	try
	{
		decoder.ingestStream (s);
	} catch(DecoderError &err) {
		throw LowlevelError("Unable to parse sleigh specfile: " + specfile);
	}

	uint4 elemId = decoder.openElement(ELEM_LANGUAGE_DEFINITIONS);
	for (;;) {
		uint4 subId = decoder.peekElement();
		if (subId == 0) {
			break;
		}
		if (subId == ELEM_LANGUAGE) {
			description.emplace_back ();
			description.back ().decode (decoder);
		} else {
			decoder.openElement ();
			decoder.closeElementSkipping (subId);
		}
	}
	decoder.closeElement (elemId);
}

/*
 * From sleigh_arch.cc's collectSpecFiles()
 * This function is used to collect all .ldefs files.
 */
void SleighAsm::collectSpecfiles(void) {
	if (!description.empty ()) {
		return;
	}
	std::vector<std::string> testspecs;
	std::vector<std::string>::iterator iter;
	specpaths.matchList(testspecs, ".ldefs", true);
	for (iter = testspecs.begin(); iter != testspecs.end (); iter++) {
		loadLanguageDescription (*iter);
	}
}


RConfig *SleighAsm::getConfig(RCore *core) {
	if (core == nullptr) {
		if (Gcore == nullptr) {
			throw LowlevelError ("Can't get RCore from RAnal's RCoreBind");
		} else {
			core = Gcore;
		}
	}
	return core->config;
}

RConfig *SleighAsm::getConfig(RAnal *a) {
	RCore *core = a ? (RCore *)a->coreb.core : nullptr;
	if (core == nullptr) {
		if (Gcore == nullptr) {
			throw LowlevelError ("Can't get RCore from RAnal's RCoreBind");
		} else {
			core = Gcore;
		}
	}
	return core->config;
}

std::string SleighAsm::getSleighHome(RConfig * R_NULLABLE cfg) {
	const char varname[] = "r2ghidra.sleighhome";

	// user-set, for example from .radare2rc
	if (cfg != nullptr) {
		const char *val = r_config_get (cfg, varname);
		if (R_STR_ISNOTEMPTY (val)) {
			return std::string (val);
		}
	}

	// SLEIGHHOME env
	char *ev = r_sys_getenv ("SLEIGHHOME");
	if (R_STR_ISNOTEMPTY (ev)) {
		if (cfg) {
			r_config_set (cfg, varname, ev);
		}
		std::string res (ev);
		return res;
	}

	char *path = r_xdg_datadir ("radare2/plugins/r2ghidra_sleigh");
	if (r_file_is_directory (path)) {
		if (cfg) {
			r_config_set (cfg, varname, path);
		}
		std::string res (path);
		return res;
	}
	free ((void *)path);
	path = strdup (R2_PREFIX "/lib/radare2/" R2_VERSION "/r2ghidra_sleigh");
	if (r_file_is_directory (path)) {
		if (cfg) {
			r_config_set (cfg, varname, path);
		}
		std::string res (path);
		return res;
	} else {
#ifdef R2GHIDRA_SLEIGHHOME_DEFAULT
		if (r_file_is_directory (R2GHIDRA_SLEIGHHOME_DEFAULT)) {
			if (cfg) {
				r_config_set (cfg, varname, R2GHIDRA_SLEIGHHOME_DEFAULT);
			}
			std::string res (R2GHIDRA_SLEIGHHOME_DEFAULT);
			return res;
		}
#endif
		R_LOG_ERROR ("Cannot find the sleigh home at '%s'. Fix it with `r2pm -ci r2ghidra-sleigh`", path);
		free (path);
		throw LowlevelError ("Missing r2ghidra_sleigh");
	}
}

int SleighAsm::disassemble(RAnalOp *op, unsigned long long offset) {
	AssemblySlg assem (this);
	Address addr(trans.getDefaultCodeSpace (), offset);
	int length = 0;
	try {
		length = trans.printAssembly (assem, addr);
		char *d = strdup (assem.str);
		r_str_case (d, false);
		free (op->mnemonic);
		op->mnemonic = d;
	} catch (BadDataError &err) {
		/* Meet unknown data -> invalid opcode */
		free (op->mnemonic);
		op->mnemonic = strdup ("invalid");
		length = alignment;
	} catch (UnimplError &err) {
		/* Meet unimplemented data -> invalid opcode */
		free (op->mnemonic);
		op->mnemonic = strdup ("invalid");
		length = alignment;
	}
	return length;
}

int SleighAsm::genOpcode(PcodeSlg &pcode_slg, Address &addr) {
	int length = 0;
	try {
		length = trans.oneInstruction(pcode_slg, addr);
	} catch (BadDataError &err) {
		/* Meet unknown data -> invalid opcode */
		length = -1;
	} catch (UnimplError &err) {
		/* Meet unimplemented data -> invalid opcode */
		length = -1;
	}
	return length;
}

void SleighAsm::initRegMapping(void) {
	reg_mapping.clear();
	std::map<VarnodeData, std::string> reglist;
	std::set<std::string> S;
	trans.getAllRegisters(reglist);

	for (auto iter = reglist.cbegin(); iter != reglist.cend (); iter++) {
		std::string tmp;
		for (auto p = iter->second.cbegin(); p != iter->second.cend (); p++) {
			tmp.push_back (std::tolower(*p));
		}
		while (S.count(tmp)) {
			tmp += "_dup";
		}
		S.insert(tmp);
		reg_mapping[iter->second] = tmp;
	}
}

std::vector<R2Reg> SleighAsm::getRegs(void) {
	std::map<VarnodeData, std::string> reglist;
	std::vector<R2Reg> r2_reglist;
	trans.getAllRegisters(reglist);

	size_t offset = 0, offset_last = reglist.begin()->first.size;
	size_t sleigh_offset = reglist.begin()->first.offset;
	size_t sleigh_last = reglist.begin()->first.size + sleigh_offset;

	for (auto p = reglist.begin(); p != reglist.end (); p++) {
		// Assume reg's size must be > 0, but mips???
		if (sleigh_last <= p->first.offset) {
			offset = offset_last;
			offset_last += p->first.size;
			sleigh_offset = p->first.offset;
			sleigh_last = sleigh_offset + p->first.size;
		}
		auto r = R2Reg{p->second, p->first.size, p->first.offset - sleigh_offset + offset};
		r2_reglist.push_back (r);
	}

	return r2_reglist;
}

ostream &operator<<(ostream &s, const PcodeOperand &arg) {
	switch (arg.type) {
	case PcodeOperand::REGISTER:
		s << arg.name;
		break;
	case PcodeOperand::UNIQUE:
		s << "unique(" << arg.offset << ", " << arg.size << ")";
		break;
	// case PcodeOperand::RAM: s << "ram(" << arg.offset << ", " << arg.size << ")";
	case PcodeOperand::RAM:
		s << arg.offset;
		break;
	case PcodeOperand::CONSTANT:
		s << arg.number;
		break;
	default:
		throw LowlevelError ("Unexpected type of PcodeOperand found in operator<<.");
	}
	return s;
}

ostream &operator<<(ostream &s, const Pcodeop &op) {
	if (op.output) {
		s << *op.output << " = ";
	}
	s << get_opname (op.type);
	if (op.input0) {
		s << " " << *op.input0;
	}
	if (op.input1) {
		s << " " << *op.input1;
	}
	return s;
}

void AssemblySlg::dump(const Address &addr, const string &mnem, const string &body) {
	std::string res;
	for (ut64 i = 0; i < body.size();) {
		std::string tmp;
		while (i < body.size() && !std::isalnum(body[i])) {
			res.push_back(body[i++]);
		}
		while (i < body.size() && std::isalnum(body[i])) {
			tmp.push_back(body[i++]);
		}
		if (sasm->reg_mapping.find(tmp) != sasm->reg_mapping.end ()) {
			res += sasm->reg_mapping[tmp];
		} else {
			res += tmp;
		}
	}
	str = (res.empty ())
		?  r_str_newf ("%s", mnem.c_str ())
		: r_str_newf("%s %s", mnem.c_str (), res.c_str ());
}

PcodeOperand *PcodeSlg::parse_vardata(VarnodeData &data) {
	AddrSpace *space = data.space;
	PcodeOperand *operand = nullptr;
	auto name = space->getName ();
	if (name == "register" || name == "mem") {
		operand = new PcodeOperand(sanal->reg_mapping[space->getTrans()->getRegisterName(
					data.space, data.offset, data.size)], data.size);
		operand->type = PcodeOperand::REGISTER;
	} else if (name == "ram" || name == "DATA" || name == "code") {
		operand = new PcodeOperand(data.offset, data.size);
		operand->type = PcodeOperand::RAM;
	} else if (name == "const") {
		// space.cc's ConstantSpace::printRaw()
		operand = new PcodeOperand (data.offset);
		operand->type = PcodeOperand::CONSTANT;
		operand->size = data.size; // To aviod ctor's signature collide with RAM's
	} else if (name == "unique") {
		operand = new PcodeOperand(data.offset, data.size);
		operand->type = PcodeOperand::UNIQUE;
	} else {
		throw LowlevelError ("Unsupported AddrSpace type appear.");
	}
	return operand;
}

void SleighAsm::check(ut64 offset, const ut8 *buf, int len) { // To refresh cache when file content is modified.
	ParserContext *ctx = trans.getContext (Address(trans.getDefaultCodeSpace(), offset), ParserContext::uninitialized);
	if (ctx->getParserState () > ParserContext::uninitialized) {
		ut8 *cached = ctx->getBuffer ();
		size_t i = 0;
		for (; i < len && cached[i] == buf[i]; i++) {
			// just loop in here
		}
		if (i != len) {
			ctx->setParserState (ParserContext::uninitialized);
		}
	}
}
