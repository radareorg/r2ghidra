/* r2ghidra - LGPL - Copyright 2019-2026 - pancake */

#include <inject_sleigh.hh>
#include <userop.hh>

namespace {

// Dalvik-only: detect whether this r2ghidra architecture is using a Dalvik SLEIGH id.
static bool isR2DalvikArchitecture(const Architecture *arch) {
	const R2Architecture *r2arch = dynamic_cast<const R2Architecture *> (arch);
	return r2arch && r2arch->getTarget ().rfind ("Dalvik:", 0) == 0;
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
