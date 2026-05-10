/* r2ghidra - LGPL - Copyright 2019-2026 - pancake */

#include <inject_sleigh.hh>
#include <marshal.hh>
#include <userop.hh>

#include <iomanip>
#include <sstream>

namespace {

enum R2DalvikCpoolTag {
	R2_DALVIK_CPOOL_METHOD = 0,
	R2_DALVIK_CPOOL_FIELD = 1,
	R2_DALVIK_CPOOL_STATIC_FIELD = 2,
	R2_DALVIK_CPOOL_STATIC_METHOD = 3,
	R2_DALVIK_CPOOL_STRING = 4,
	R2_DALVIK_CPOOL_CLASSREF = 5,
	R2_DALVIK_CPOOL_ARRAYLENGTH = 6,
	R2_DALVIK_CPOOL_SUPER = 7,
	R2_DALVIK_CPOOL_INSTANCEOF = 8,
};

// Dalvik-only: detect whether this r2ghidra architecture is using a Dalvik SLEIGH id.
static bool isR2DalvikArchitecture(const Architecture *arch) {
	const R2Architecture *r2arch = dynamic_cast<const R2Architecture *> (arch);
	return r2arch && r2arch->getTarget ().rfind ("Dalvik:", 0) == 0;
}

// Dalvik-only: keep decompiler tokens printable in C-like output.
static std::string r2DalvikToken(const std::string &name) {
	std::string result;
	result.reserve (name.size ());
	for (char ch : name) {
		unsigned char uch = static_cast<unsigned char> (ch);
		if (isalnum (uch) || ch == '_') {
			result.push_back (ch);
		} else {
			result.push_back ('_');
		}
	}
	if (result.empty ()) {
		return "dex_ref";
	}
	if (isdigit (static_cast<unsigned char> (result[0]))) {
		result.insert (result.begin (), '_');
	}
	return result;
}

// Dalvik-only: turn a DEX type descriptor into a stable C token.
static std::string r2DalvikDescriptorToken(const std::string &descriptor) {
	if (descriptor.size () > 2 && descriptor[0] == 'L' && descriptor.back () == ';') {
		return r2DalvikToken (descriptor.substr (1, descriptor.size () - 2));
	}
	return r2DalvikToken (descriptor);
}

class R2DalvikConstantPool : public ConstantPoolInternal {
	R2Architecture *arch;

	// Dalvik-only: use the current rbin plugin just like r2's Dalvik disassembler does.
	std::string r2BinName(int type, uint4 index) const {
		std::string result;
		RCoreLock core (arch->getCore ());
		if (!core || !core->bin || !core->bin->cur) {
			return result;
		}
		RBinFile *bf = core->bin->cur;
		RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
		if (!plugin || !plugin->get_name) {
			return result;
		}
		const char *name = plugin->get_name (bf, type, index, false);
		if (name) {
			result = name;
			if (plugin->meta.name && !strcmp (plugin->meta.name, "dex") && type != 'p') {
				free (const_cast<char *> (name));
			}
		}
		return result;
	}

	// Dalvik-only: use rbin's indexed offset resolver for DEX strings and fields.
	ut64 r2BinOffset(int type, uint4 index) const {
		RCoreLock core (arch->getCore ());
		if (!core || !core->bin || !core->bin->cur) {
			return UT64_MAX;
		}
		RBinFile *bf = core->bin->cur;
		RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
		if (!plugin || !plugin->get_offset) {
			return UT64_MAX;
		}
		return plugin->get_offset (bf, type, index);
	}

	// Dalvik-only: read a DEX string payload from an offset already resolved by rbin.
	std::string stringAtOffset(ut64 offset) const {
		uint1 uleb[6] = {};
		{
			RCoreLock core (arch->getCore ());
			if (!core || !core->io || !r_io_read_at (core->io, offset, uleb, sizeof (uleb))) {
				return std::string ();
			}
		}
		ut64 dataOffset = offset;
		uint4 shift = 0;
		for (uint4 i = 0; i < sizeof (uleb); i++) {
			dataOffset++;
			if (!(uleb[i] & 0x80)) {
				std::string result;
				for (uint4 total = 0; total < 0x10000; ) {
					uint1 buffer[256] = {};
					RCoreLock core (arch->getCore ());
					if (!core || !core->io || !r_io_read_at (core->io, dataOffset + total, buffer, sizeof (buffer))) {
						return result;
					}
					for (uint4 j = 0; j < sizeof (buffer) && total < 0x10000; j++, total++) {
						if (!buffer[j]) {
							return result;
						}
						result.push_back (static_cast<char> (buffer[j]));
					}
				}
				return result;
			}
			shift += 7;
			if (shift >= 35) {
				break;
			}
		}
		return std::string ();
	}

	Datatype *descriptorType(const std::string &descriptor) {
		if (descriptor == "V") {
			return arch->types->getTypeVoid ();
		}
		if (descriptor == "Z") {
			return arch->types->getBase (1, TYPE_BOOL);
		}
		if (descriptor == "B") {
			return arch->types->getBase (1, TYPE_INT);
		}
		if (descriptor == "S") {
			return arch->types->getBase (2, TYPE_INT);
		}
		if (descriptor == "C") {
			return arch->types->getBase (2, TYPE_UINT);
		}
		if (descriptor == "I") {
			return arch->types->getBase (4, TYPE_INT);
		}
		if (descriptor == "J") {
			return arch->types->getBase (8, TYPE_INT);
		}
		if (descriptor == "F") {
			return arch->types->getBase (4, TYPE_FLOAT);
		}
		if (descriptor == "D") {
			return arch->types->getBase (8, TYPE_FLOAT);
		}
		std::string token = r2DalvikDescriptorToken (descriptor);
		Datatype *base = arch->types->getBase (1, TYPE_UNKNOWN, token);
		return arch->types->getTypePointer (4, base, 1);
	}

	// Dalvik-only: extract a DEX field descriptor from rbin's field name string.
	std::string fieldDescriptor(uint4 index) {
		std::string name = r2BinName ('f', index);
		size_t space = name.rfind (' ');
		if (space != std::string::npos && space + 1 < name.size ()) {
			return name.substr (space + 1);
		}
		return std::string ();
	}

	Datatype *fieldPointerType(uint4 index) {
		Datatype *fieldType = descriptorType (fieldDescriptor (index));
		return arch->types->getTypePointer (4, fieldType, 1);
	}

	Datatype *methodPointerType() {
		return arch->types->getTypePointer (4, arch->types->getTypeCode (), 1);
	}

	Datatype *classReferenceType(const std::string &token) {
		Datatype *base = arch->types->getBase (1, TYPE_UNKNOWN, token);
		return arch->types->getTypePointer (4, base, 1);
	}

	// Dalvik-only: resolve method table names through rbin.
	std::string methodToken(uint4 index) {
		std::string name = r2BinName ('m', index);
		if (!name.empty ()) {
			return r2DalvikToken (name);
		}
		return "method_" + std::to_string (index);
	}

	// Dalvik-only: resolve field table names through rbin.
	std::string fieldToken(uint4 index, bool includeClass) {
		std::string name = r2BinName ('f', index);
		if (!name.empty ()) {
			size_t space = name.find (' ');
			if (space != std::string::npos) {
				name.resize (space);
			}
			size_t arrow = name.find ("->");
			if (arrow != std::string::npos && arrow + 2 < name.size ()) {
				if (includeClass) {
					name = name.substr (0, arrow) + "_" + name.substr (arrow + 2);
				} else {
					name = name.substr (arrow + 2);
				}
			}
			return r2DalvikToken (name);
		}
		return "field_" + std::to_string (index);
	}

	// Dalvik-only: resolve type table names through rbin.
	std::string classToken(uint4 index) {
		std::string name = r2BinName ('c', index);
		if (!name.empty ()) {
			return r2DalvikDescriptorToken (name);
		}
		return "type_" + std::to_string (index);
	}

	// Dalvik-only: use r2 metadata first, then read at the rbin-resolved DEX string offset.
	std::string stringLiteral(uint4 index) {
		ut64 offset = r2BinOffset ('s', index);
		if (offset != UT64_MAX) {
			{
				RCoreLock core (arch->getCore ());
				if (core && core->anal) {
					const char *meta = r_meta_get_string (core->anal, R_META_TYPE_STRING, offset);
					if (meta && *meta) {
						return meta;
					}
				}
				if (core && core->bin && core->bin->cur && core->bin->cur->bo && core->bin->cur->bo->strings_db) {
					RBinString *binstr = reinterpret_cast<RBinString *> (
						ht_up_find (core->bin->cur->bo->strings_db, offset, nullptr));
					if (binstr && binstr->string && *binstr->string) {
						return binstr->string;
					}
				}
			}
			return stringAtOffset (offset);
		}
		return std::string ();
	}

	void putStringRecord(const std::vector<uintb> &refs, const std::string &value) {
		std::ostringstream xml;
		xml << "<cpoolrec tag=\"string\"><data length=\"" << value.size () << "\">";
		for (unsigned char ch : value) {
			xml << std::setfill ('0') << std::setw (2) << std::hex << static_cast<unsigned int> (ch) << ' ';
		}
		xml << "</data><type name=\"uint8_t\" size=\"1\" metatype=\"uint\" core=\"true\"/></cpoolrec>";
		std::istringstream stream (xml.str ());
		XmlDecode decoder (arch);
		decoder.ingestStream (stream);
		decodeRecord (refs, decoder, *arch->types);
	}

	void resolveRecord(const std::vector<uintb> &refs) {
		if (refs.size () < 2) {
			return;
		}
		uint4 index = static_cast<uint4> (refs[0]);
		uint4 tag = static_cast<uint4> (refs[1]);
		switch (tag) {
		case R2_DALVIK_CPOOL_METHOD:
		case R2_DALVIK_CPOOL_STATIC_METHOD:
			putRecord (refs, CPoolRecord::pointer_method, methodToken (index), methodPointerType ());
			break;
		case R2_DALVIK_CPOOL_FIELD:
			putRecord (refs, CPoolRecord::pointer_field, fieldToken (index, false), fieldPointerType (index));
			break;
		case R2_DALVIK_CPOOL_STATIC_FIELD:
			putRecord (refs, CPoolRecord::pointer_field, fieldToken (index, true), fieldPointerType (index));
			break;
		case R2_DALVIK_CPOOL_STRING:
			putStringRecord (refs, stringLiteral (index));
			break;
		case R2_DALVIK_CPOOL_CLASSREF:
			{
				std::string token = classToken (index);
				putRecord (refs, CPoolRecord::class_reference, token, classReferenceType (token));
			}
			break;
		case R2_DALVIK_CPOOL_ARRAYLENGTH:
			putRecord (refs, CPoolRecord::array_length, "length", arch->types->getBase (4, TYPE_INT));
			break;
		case R2_DALVIK_CPOOL_SUPER:
			putRecord (refs, CPoolRecord::class_reference, "super", arch->types->getBase (4, TYPE_UNKNOWN));
			break;
		case R2_DALVIK_CPOOL_INSTANCEOF:
			{
				std::string token = classToken (index);
				putRecord (refs, CPoolRecord::instance_of, "instanceof", classReferenceType (token));
			}
			break;
		default:
			break;
		}
	}

public:
	// Dalvik-only: resolve SLEIGH cpool(index, tag) references against the loaded DEX tables.
	explicit R2DalvikConstantPool(R2Architecture *a) : arch (a) {
	}

	// Dalvik-only: lazily materialize CPoolRecords so PrintC stops emitting UNKNOWNREF.
	const CPoolRecord *getRecord(const std::vector<uintb> &refs) const override {
		const CPoolRecord *record = ConstantPoolInternal::getRecord (refs);
		if (record) {
			return record;
		}
		const_cast<R2DalvikConstantPool *> (this)->resolveRecord (refs);
		return ConstantPoolInternal::getRecord (refs);
	}
};

// Dalvik-only: install the DEX-aware pool for Dalvik and keep the standard empty pool elsewhere.
static ConstantPool *buildR2DalvikConstantPool(R2Architecture *arch) {
	if (isR2DalvikArchitecture (arch)) {
		return new R2DalvikConstantPool (arch);
	}
	return new ConstantPoolInternal ();
}

// Dalvik-only: emit Ghidra's Java-side moveRangeToIV dynamic inject as native p-code.
static void emitR2DalvikMoveRangeToIV(InjectContext &context, PcodeEmit &emit) {
	if (context.inputlist.size () != 2) {
		throw LowlevelError ("moveRangeToIV expects 2 inputs");
	}
	const VarnodeData &countVn = context.inputlist[0];
	const VarnodeData &fromVn = context.inputlist[1];
	if (!countVn.space || countVn.space->getType () != IPTR_CONSTANT) {
		throw LowlevelError ("moveRangeToIV parameter count must be constant");
	}
	AddrSpace *registerSpace = context.glb->getSpaceByName ("register");
	if (!registerSpace || fromVn.space != registerSpace) {
		throw LowlevelError ("moveRangeToIV source must be in register space");
	}
	uintb fromOffset = fromVn.offset;
	uintb toOffset = 0x100; // Dalvik iv0
	uintb count = countVn.offset;
	if (count == 0) {
		VarnodeData nop;
		nop.space = registerSpace;
		nop.offset = toOffset;
		nop.size = 4;
		emit.dump (context.baseaddr, CPUI_COPY, &nop, &nop, 1);
		return;
	}
	for (uintb i = 0; i < count; i++) {
		VarnodeData input;
		VarnodeData output;
		input.space = registerSpace;
		input.offset = fromOffset;
		input.size = 4;
		output.space = registerSpace;
		output.offset = toOffset;
		output.size = 4;
		emit.dump (context.baseaddr, CPUI_COPY, &output, &input, 1);
		fromOffset += 4;
		toOffset += 4;
	}
}

// Dalvik-only: emit Ghidra's Java-side uponentry parameter staging as native p-code.
static void emitR2DalvikUponEntry(InjectContext &context, PcodeEmit &emit) {
	AddrSpace *registerSpace = context.glb->getSpaceByName ("register");
	if (!registerSpace) {
		throw LowlevelError ("Dalvik uponentry requires register space");
	}
	uintb entry = context.baseaddr.getOffset ();
	if (entry < 16) {
		return;
	}
	uint1 header[4] = {};
	context.glb->loader->loadFill (header, sizeof (header), Address (context.baseaddr.getSpace (), entry - 16));
	uint4 registersSize = header[0] | (header[1] << 8);
	uint4 incomingSize = header[2] | (header[3] << 8);
	if (incomingSize == 0 || incomingSize > registersSize) {
		return;
	}
	uintb fromOffset = 0x100; // Dalvik iv0
	uintb toOffset = 0x1000 + 4 * (registersSize - incomingSize);
	for (uint4 i = 0; i < incomingSize; i++) {
		VarnodeData input;
		VarnodeData output;
		input.space = registerSpace;
		input.offset = fromOffset;
		input.size = 4;
		output.space = registerSpace;
		output.offset = toOffset;
		output.size = 4;
		emit.dump (context.baseaddr, CPUI_COPY, &output, &input, 1);
		fromOffset += 4;
		toOffset += 4;
	}
}

class R2DalvikCallMechanismPayload : public InjectPayloadSleigh {
public:
	// Dalvik-only: wrap CALLMECHANISM payloads so @@inject_uponentry can run without Java.
	R2DalvikCallMechanismPayload(const std::string &sourceName, const std::string &name)
		: InjectPayloadSleigh (sourceName, name, CALLMECHANISM_TYPE) {
		incidentalCopy = true;
	}

	// Dalvik-only: service @@inject_uponentry and delegate every other call mechanism.
	void inject(InjectContext &context, PcodeEmit &emit) const override {
		if (isR2DalvikArchitecture (context.glb) && getName ().find ("@@inject_uponentry") != std::string::npos) {
			emitR2DalvikUponEntry (context, emit);
			return;
		}
		InjectPayloadSleigh::inject (context, emit);
	}
};

class R2DalvikCallotherPayload : public InjectPayloadCallother {
public:
	// Dalvik-only: wrap callother payloads so moveRangeToIV can run without Java.
	explicit R2DalvikCallotherPayload(const std::string &sourceName) : InjectPayloadCallother (sourceName) {
		incidentalCopy = true;
	}

	// Dalvik-only: service moveRangeToIV and delegate every other callother fixup.
	void inject(InjectContext &context, PcodeEmit &emit) const override {
		if (getName () == "moveRangeToIV") {
			emitR2DalvikMoveRangeToIV (context, emit);
			return;
		}
		InjectPayloadSleigh::inject (context, emit);
	}
};

class R2DalvikMoveRangeToIVPayload : public InjectPayload {
public:
	// Dalvik-only: create a manual moveRangeToIV payload when a stripped cspec leaves it unresolved.
	R2DalvikMoveRangeToIVPayload() : InjectPayload ("moveRangeToIV", CALLOTHERFIXUP_TYPE) {
		incidentalCopy = true;
		inputlist.push_back (InjectParameter ("count", 4));
		inputlist.push_back (InjectParameter ("start", 4));
		orderParameters ();
	}

	// Dalvik-only: emit the manual moveRangeToIV fallback.
	void inject(InjectContext &context, PcodeEmit &emit) const override {
		emitR2DalvikMoveRangeToIV (context, emit);
	}

	// Dalvik-only: this payload is constructed by r2ghidra, not decoded from XML.
	void decode(Decoder &decoder) override {
		throw LowlevelError ("moveRangeToIV is registered by r2ghidra");
	}

	// Dalvik-only: describe the native moveRangeToIV fallback in debug dumps.
	void printTemplate(std::ostream &s) const override {
		s << "r2ghidra moveRangeToIV";
	}

	// Dalvik-only: report that this fallback payload is owned by r2ghidra.
	std::string getSource() const override {
		return "r2ghidra";
	}
};

class R2DalvikPcodeInjectLibrary : public PcodeInjectLibrarySleigh {
protected:
	// Dalvik-only: allocate Dalvik wrappers for payload kinds that can contain Java-side dynamic injects.
	int4 allocateInject(const std::string &sourceName, const std::string &name, int4 type) override {
		if (isR2DalvikArchitecture (glb) && type == InjectPayload::CALLOTHERFIXUP_TYPE) {
			int4 injectid = injection.size ();
			injection.push_back (new R2DalvikCallotherPayload (sourceName));
			return injectid;
		}
		if (isR2DalvikArchitecture (glb) && type == InjectPayload::CALLMECHANISM_TYPE) {
			int4 injectid = injection.size ();
			injection.push_back (new R2DalvikCallMechanismPayload (sourceName, name));
			return injectid;
		}
		return PcodeInjectLibrarySleigh::allocateInject (sourceName, name, type);
	}

	// Dalvik-only: register known dynamic injects directly; all other payloads follow normal handling.
	void registerInject(int4 injectid) override {
		InjectPayload *payload = injection[injectid];
		if (payload->getType () == InjectPayload::CALLOTHERFIXUP_TYPE && payload->getName () == "moveRangeToIV") {
			registerCallOtherFixup (payload->getName (), injectid);
			return;
		}
		if (isR2DalvikArchitecture (glb) && payload->getType () == InjectPayload::CALLMECHANISM_TYPE &&
				payload->getName ().find ("@@inject_uponentry") != std::string::npos) {
			registerCallMechanism (payload->getName (), injectid);
			return;
		}
		PcodeInjectLibrarySleigh::registerInject (injectid);
	}

public:
	// Dalvik-only: this library delegates all non-Dalvik payloads to PcodeInjectLibrarySleigh.
	explicit R2DalvikPcodeInjectLibrary(Architecture *g) : PcodeInjectLibrarySleigh (g) {
	}

	// Dalvik-only: provide moveRangeToIV when older local cspecs suppress the dynamic XML entry.
	int4 manualCallOtherFixup(const std::string &name, const std::string &outname,
			const std::vector<std::string> &inname, const std::string &snippet) override {
		if (name == "moveRangeToIV") {
			int4 injectid = injection.size ();
			injection.push_back (new R2DalvikMoveRangeToIVPayload ());
			registerCallOtherFixup (name, injectid);
			return injectid;
		}
		return PcodeInjectLibrarySleigh::manualCallOtherFixup (name, outname, inname, snippet);
	}
};

// Dalvik-only: expose the Dalvik-aware injection library to R2Architecture.
static PcodeInjectLibrary *buildR2DalvikPcodeInjectLibrary(R2Architecture *arch) {
	return new R2DalvikPcodeInjectLibrary (arch);
}

// Dalvik-only: attach moveRangeToIV after spec load when a legacy cspec left it unspecialized.
static void registerR2DalvikPostSpecInjects(R2Architecture *arch) {
	if (!isR2DalvikArchitecture (arch)) {
		return;
	}
	UserPcodeOp *op = arch->userops.getOp ("moveRangeToIV");
	if (op && op->getType () == UserPcodeOp::unspecialized) {
		std::vector<std::string> inputs = { "count", "start" };
		arch->userops.manualCallOtherFixup ("moveRangeToIV", "", inputs, "", arch);
	}
}

}
