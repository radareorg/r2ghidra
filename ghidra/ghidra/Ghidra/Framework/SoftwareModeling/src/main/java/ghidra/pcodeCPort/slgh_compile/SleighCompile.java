/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.pcodeCPort.slgh_compile;

import java.io.IOException;
import java.io.PrintStream;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.antlr.runtime.RecognitionException;
import org.jdom.JDOMException;

import generic.stl.*;
import ghidra.pcode.utils.MessageFormattingUtils;
import ghidra.pcodeCPort.address.Address;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.pcodeCPort.semantics.*;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghpatexpress.*;
import ghidra.pcodeCPort.slghsymbol.*;
import ghidra.pcodeCPort.space.*;
import ghidra.pcodeCPort.utils.Utils;
import ghidra.pcodeCPort.xml.DocumentStorage;
import ghidra.program.model.lang.BasicCompilerSpec;
import ghidra.sleigh.grammar.Location;
import ghidra.util.Msg;

/**
 * <code>SleighCompile</code> provides the ability to compile Sleigh language module (e.g., *.slaspec)
 * files.
 */
public class SleighCompile extends SleighBase {

	static boolean yydebug = false;

	static boolean isLocationIsh(Object o) {
		if (o instanceof Location) {
			return true;
		}
		if (o instanceof List) {
			List<?> l = (List<?>) o;
			for (Object t : l) {
				if (isLocationIsh(t)) {
					return true;
				}
			}
		}
		if (o instanceof VectorSTL) {
			VectorSTL<?> v = (VectorSTL<?>) o;
			for (Object t : v) {
				if (isLocationIsh(t)) {
					return true;
				}
			}
		}
		return false;
	}

	public static void entry(String name, Object... args) {
		StringBuilder sb = new StringBuilder();
		sb.append(name).append("(");
		// @formatter:off
		sb.append(Arrays.stream(args)
			.filter(a -> isLocationIsh(a))
			.map(Object::toString)
			.collect(Collectors.joining(", ")));
		// @formatter:on
		sb.append(")");
		Msg.trace(SleighCompile.class, sb.toString());
	}

	// Semantic pcode compiler
	public final PcodeCompile pcode = new PcodeCompile() {

		@Override
		public void reportError(Location location, String msg) {
			SleighCompile.this.reportError(location, msg);
		}

		@Override
		public void reportWarning(Location location, String msg) {
			SleighCompile.this.reportWarning(location, msg);
		}

		@Override
		public int getErrors() {
			return SleighCompile.this.numErrors();
		}

		@Override
		public int getWarnings() {
			return SleighCompile.this.numWarnings();
		}

		@Override
		public AddrSpace getConstantSpace() {
			return SleighCompile.this.getConstantSpace();
		}

		@Override
		public AddrSpace getDefaultSpace() {
			return SleighCompile.this.getDefaultSpace();
		}

		@Override
		public AddrSpace getUniqueSpace() {
			return SleighCompile.this.getUniqueSpace();
		}

		@Override
		public void addSymbol(SleighSymbol sym) {
			SleighCompile.this.addSymbol(sym);
		}

		@Override
		public SleighSymbol findSymbol(String nm) {
			return SleighCompile.this.findSymbol(nm);
		}

		@Override
		public long allocateTemp() {
			return getUniqueAddr();
		}

		@Override
		public void recordNop(Location location) {
			SleighCompile.this.recordNop(location);
		}

		@Override
		public VectorSTL<OpTpl> createMacroUse(Location location, MacroSymbol sym,
				VectorSTL<ExprTree> param) {
			return SleighCompile.this.createMacroUse(location, sym, param);
		}

		@Override
		public SectionSymbol newSectionSymbol(Location where, String text) {
			return SleighCompile.this.newSectionSymbol(where, text);
		}

		@Override
		public VectorSTL<OpTpl> createCrossBuild(Location find, VarnodeTpl v,
				SectionSymbol section) {
			return SleighCompile.this.createCrossBuild(find, v, section);
		}

		@Override
		public SectionVector standaloneSection(ConstructTpl c) {
			return SleighCompile.this.standaloneSection(c);
		}

		@Override
		public SectionVector firstNamedSection(ConstructTpl main, SectionSymbol sym) {
			return SleighCompile.this.firstNamedSection(main, sym);
		}

		@Override
		public SectionVector nextNamedSection(SectionVector vec, ConstructTpl section,
				SectionSymbol sym) {
			return SleighCompile.this.nextNamedSection(vec, section, sym);
		}

		@Override
		public SectionVector finalNamedSection(SectionVector vec, ConstructTpl section) {
			return SleighCompile.this.finalNamedSection(vec, section);
		}
	};

	protected static class WithBlock {
		SubtableSymbol ss;
		PatternEquation pateq;
		VectorSTL<ContextChange> contvec;

		WithBlock(SubtableSymbol ss, PatternEquation pateq, VectorSTL<ContextChange> contvec) {
			this.ss = ss;
			this.pateq = pateq;
			this.contvec = contvec;
		}

		static PatternEquation collectAndPrependPattern(Deque<WithBlock> stack,
				PatternEquation pateq) {
			for (WithBlock with : stack) {
				if (with.pateq != null) {
					pateq = new EquationAnd(null, with.pateq, pateq);
				}
			}
			return pateq;
		}

		static VectorSTL<ContextChange> collectAndPrependContext(Deque<WithBlock> stack,
				VectorSTL<ContextChange> contvec) {
			for (WithBlock with : stack) {
				if (with.contvec != null) {
					contvec.insertAll(contvec.begin(), with.contvec);
				}
			}
			return contvec;
		}

		static SubtableSymbol getCurrentSubtable(Deque<WithBlock> stack) {
			for (WithBlock with : stack) {
				if (with.ss != null) {
					return with.ss;
				}
			}
			return null;
		}
	}

	// Defines for the preprocessor
	MapSTL<String, String> preproc_defines = new MapSTL<>(new SelfComparator<String>());
	VectorSTL<FieldContext> contexttable = new VectorSTL<>();
	Integer firstContextField = null;
	VectorSTL<ConstructTpl> macrotable = new VectorSTL<>();
	VectorSTL<ghidra.pcodeCPort.context.Token> tokentable = new VectorSTL<>();
	VectorSTL<SubtableSymbol> tables = new VectorSTL<>();
	VectorSTL<SectionSymbol> sections = new VectorSTL<>();
	Constructor curct; // Current constructor being defined
	MacroSymbol curmacro; // Current macro being defined

	// If the context layout has been established yet
	boolean contextlock;

	// Stack of current files being parsed
//    VectorSTL<String> filename = new VectorSTL<String>();
	String filename;

	// Current line number for each file in stack
//    VectorSTL<Integer> lineno = new VectorSTL<Integer>(); 
	int lineno;
	int linenoDifferential;

	int userop_count; // Number of userops defined

	boolean warnunnecessarypcode;	// True if we warn of unnecessary ZEXT or SEXT
	boolean warndeadtemps;		// True if we warn of temporaries that are written but not read
	boolean warnunusedfields;   // True if fields are defined but not used
	boolean enforcelocalkeyword;  // Force slaspec to use 'local' keyword when defining temporary varnodes
	boolean lenientconflicterrors; // True if we ignore most pattern conflict errors
	public boolean warnalllocalcollisions;
	public boolean warnallnops;
	public VectorSTL<String> noplist = new VectorSTL<>();

	public Deque<WithBlock> withstack = new LinkedList<>();

	int errors;
	int warnings;

	// Define the "pre" defined spaces and symbols
	// This must happen after endian has been defined
	void predefinedSymbols() {
		entry("predefinedSymbols");
		symtab.addScope(); // Create global scope

		Location location = Location.INTERNALLY_DEFINED;
		// Some predefined symbols
		root = new SubtableSymbol(location, "instruction"); // Base constructors
		symtab.addSymbol(root);
		insertSpace(new ConstantSpace(this, "const", BasicCompilerSpec.CONSTANT_SPACE_INDEX));
		SpaceSymbol spacesym = new SpaceSymbol(location, getConstantSpace()); // Constant
		// space
		symtab.addSymbol(spacesym);
		OtherSpace otherSpace = new OtherSpace(this, BasicCompilerSpec.OTHER_SPACE_NAME,
			BasicCompilerSpec.OTHER_SPACE_INDEX);
		insertSpace(otherSpace);
		spacesym = new SpaceSymbol(location, otherSpace);
		symtab.addSymbol(spacesym);
		insertSpace(new UniqueSpace(this, "unique", numSpaces(), 0));
		spacesym = new SpaceSymbol(location, getUniqueSpace()); // Temporary register
		// space
		symtab.addSymbol(spacesym);
		StartSymbol startsym = new StartSymbol(location, "inst_start", getConstantSpace());
		symtab.addSymbol(startsym);
		EndSymbol endsym = new EndSymbol(location, "inst_next", getConstantSpace());
		symtab.addSymbol(endsym);
		EpsilonSymbol epsilon = new EpsilonSymbol(location, "epsilon", getConstantSpace());
		symtab.addSymbol(epsilon);
	}

	protected SectionSymbol newSectionSymbol(Location location, String nm) {
		entry("newSectionSymbol", location, nm);
		SectionSymbol sym = new SectionSymbol(location, nm, sections.size());
		try {
			symtab.addGlobalSymbol(sym);
		}
		catch (SleighError err) {
			reportError(err.location, err.getMessage());
		}
		sections.push_back(sym);
		numSections = sections.size();
		return sym;
	}

	protected VectorSTL<OpTpl> createCrossBuild(Location location, VarnodeTpl addr,
			SectionSymbol sym) {
		entry("createCrossBuild", location, addr, sym);
		// Create the crossbuild directive as a pcode template
		unique_allocatemask = 1;
		VectorSTL<OpTpl> res = new VectorSTL<>();
		VarnodeTpl sectionid = new VarnodeTpl(location, new ConstTpl(getConstantSpace()),
			new ConstTpl(ConstTpl.const_type.real, sym.getTemplateId()),
			new ConstTpl(ConstTpl.const_type.real, 4));
		// This is simply a single pcodeop (template), where the opcode indicates the crossbuild directive
		OpTpl op = new OpTpl(location, OpCode.CPUI_PTRSUB); // CROSSBUILD
		op.addInput(addr);		// The first input is the VarnodeTpl representing the address
		op.addInput(sectionid);	// The second input is the indexed representing the named pcode section to build
		res.push_back(op);
		sym.incrementRefCount();	// Keep track of the references to the section symbol
		return res;
	}

	SectionVector standaloneSection(ConstructTpl main) {
		entry("standaloneSection", main);
		// Create SectionVector for just the main rtl section with no named sections
		SectionVector res = new SectionVector(main, symtab.getCurrentScope());
		return res;
	}

	SectionVector firstNamedSection(ConstructTpl main, SectionSymbol sym) {
		entry("firstNamedSection", main);
		// Start the first named p-code section after the main p-code section
		sym.incrementDefineCount();
		SymbolScope curscope = symtab.getCurrentScope(); // This should be a Constructor scope
		SymbolScope parscope = curscope.getParent();
		if (parscope != symtab.getGlobalScope()) {
			throw new LowlevelError("firstNamedSection called when not in Constructor scope"); // Unrecoverable error
		}
		symtab.addScope();		// Add new scope under the Constructor scope
		SectionVector res = new SectionVector(main, curscope);
		res.setNextIndex(sym.getTemplateId());
		return res;
	}

	SectionVector nextNamedSection(SectionVector vec, ConstructTpl section, SectionSymbol sym) {
		entry("nextNamedSection", vec, section, sym);
		// Add additional named p-code sections
		sym.incrementDefineCount();
		SymbolScope curscope = symtab.getCurrentScope();
		symtab.popScope();		// Pop the scope of the last named section
		SymbolScope parscope = symtab.getCurrentScope().getParent();
		if (parscope != symtab.getGlobalScope()) {
			throw new LowlevelError("nextNamedSection called when not in section scope"); // Unrecoverable
		}
		symtab.addScope();		// Add new scope under the Constructor scope (not the last section scope)
		vec.append(section, curscope); // Associate finished section
		vec.setNextIndex(sym.getTemplateId()); // Set index for the NEXT section (not been fully parsed yet)
		return vec;
	}

	SectionVector finalNamedSection(SectionVector vec, ConstructTpl section) {
		entry("finalNamedSection", vec, section);
		// Fill-in final named section to match the previous SectionSymbol
		vec.append(section, symtab.getCurrentScope());
		symtab.popScope();		// Pop the section scope
		return vec;
	}

	int calcContextVarLayout(int start, int sz, int numbits) {
		entry("calcContextVarLayout", start, sz, numbits);
		VarnodeSymbol sym = contexttable.get(start).sym;
		FieldQuality qual;
		int i, j;

		final int symSize = sym.getSize();
		if (symSize % 4 != 0) {
			reportError(sym.location,
				String.format(
					"Invalid size of context register '%s' (%d); must be a multiple of 4",
					sym.getName(), symSize));
		}
		final int maxBits = symSize * 8 - 1;

		i = 0;
		while (i < sz) {

			qual = contexttable.get(i).qual;
			int min = qual.low;
			int max = qual.high;
			if (max - min > (8 * 4)) {
				reportError(qual.location,
					String.format(
						"Size of bitfield %s=(%d,%d) larger than %d bits in context register '%s'",
						qual.name, min, (8 * 4), sym.getName()));

			}
			if (max > maxBits) {
				reportError(qual.location, String.format(
					"Scope of bitfield %s=(%d,%d) extends beyond the size of context register '%s' (%d)",
					qual.name, min, max, sym.getName(), maxBits));
			}

			j = i + 1;
			// Find union of fields overlapping with first field
			while (j < sz) {
				qual = contexttable.get(j).qual;
				if (qual.low <= max) { // We have overlap of context variables
					if (qual.high > max) {
						max = qual.high;
						// reportWarning("Local context variables overlap in
						// "+sym.getName(),false);
					}
				}
				else {
					break;
				}
				j = j + 1;
			}

			int alloc = max - min + 1;
			int startword = Utils.unsignedDivide(numbits, (8 * 4));
			int endword = Utils.unsignedDivide((numbits + alloc - 1), (8 * 4));
			if (startword != endword) {
				numbits = endword * (8 * 4); // Bump up to next word
			}

			int low = numbits;
			numbits += alloc;

			for (; i < j; ++i) {
				qual = contexttable.get(i).qual;
				int l = qual.low - min + low;
				int h = numbits - 1 - (max - qual.high);
				ContextField field = new ContextField(qual.location, qual.signext, l, h);
				int id = addSymbol(new ContextSymbol(qual.location, qual.name, field, sym, qual.low,
					qual.high, qual.flow));
				if (firstContextField == null) {
					firstContextField = id;
				}
			}

		}
		sym.markAsContext();
		return numbits;
	}

	void buildDecisionTrees() {
		entry("buildDecisionTrees");
		DecisionProperties props = new DecisionProperties();
		root.buildDecisionTree(props);

		for (int i = 0; i < tables.size(); ++i) {
			tables.get(i).buildDecisionTree(props);
		}
		VectorSTL<String> ierrors = props.getIdentErrors();
//    		const vector<string> &ierrors( props.getIdentErrors() );
		for (int i = 0; i < ierrors.size(); ++i) {
			errors += 1;
			Msg.error(this, ierrors.get(i));
		}

		if (!lenientconflicterrors) {
			VectorSTL<String> cerrors = props.getConflictErrors();
			for (int i = 0; i < cerrors.size(); ++i) {
				errors += 1;
				Msg.error(this, cerrors.get(i));
			}
		}
	}

	void buildPatterns() {
		entry("buildPatterns");
		if (root == null) {
			reportError(null, "No patterns to match--could not find any constructors");
			return;
		}
		root.buildPattern(System.err); // This should recursively hit
		// everything
		if (root.isError()) {
			errors += 1;
		}
		for (int i = 0; i < tables.size(); ++i) {
			if (tables.get(i).isError()) {
				errors += 1;
			}
			if (tables.get(i).getPattern() == null) {
				reportWarning(tables.get(i).getLocation(),
					"Unreferenced table: '" + tables.get(i).getName() + "'");
			}
		}
	}

	void checkConsistency() {
		entry("checkConsistency");
		ConsistencyChecker checker =
			new ConsistencyChecker(this, root, warnunnecessarypcode, warndeadtemps);

		if (!checker.test()) {
			errors += 1;
			return;
		}
		if (!checker.testTruncations(isBigEndian())) {
			errors += 1;
			return;
		}
		if ((!warnunnecessarypcode) && (checker.getNumUnnecessaryPcode() > 0)) {
			reportWarning(null, checker.getNumUnnecessaryPcode() +
				" unnecessary extensions/truncations were converted to copies");
			reportWarning(null, "Use -u switch to list each individually");
		}
		checker.optimizeAll();
		if (checker.getNumReadNoWrite() > 0) {
			errors += 1;
			return;
		}
		if ((!warndeadtemps) && (checker.getNumWriteNoRead() > 0)) {
			reportWarning(null, checker.getNumWriteNoRead() +
				" operations wrote to temporaries that were not read");
			reportWarning(null, "Use -t switch to list each individually");
		}
	}

	static int findCollision(Map<Long, Integer> local2Operand, ArrayList<Long> locals,
			int operand) {
		Integer boxOperand = Integer.valueOf(operand);
		for (int i = 0; i < locals.size(); ++i) {
			Integer previous = local2Operand.putIfAbsent(locals.get(i), boxOperand);
			if (previous != null) {
				if (previous.intValue() != operand) {
					return previous.intValue();
				}
			}
		}
		return -1;
	}

	boolean checkLocalExports(Constructor ct) {
		if (ct.getTempl() == null) {
			return true;		// No template, collisions impossible
		}
		if (ct.getTempl().buildOnly()) {
			return true;		// Operand exports aren't manipulated, so no collision is possible
		}
		if (ct.getNumOperands() < 2) {
			return true;		// Collisions can only happen with multiple operands
		}
		boolean noCollisions = true;
		Map<Long, Integer> collect = new TreeMap<Long, Integer>();
		for (int i = 0; i < ct.getNumOperands(); ++i) {
			ArrayList<Long> newCollect = new ArrayList<Long>();
			ct.getOperand(i).collectLocalValues(newCollect);
			if (newCollect.isEmpty()) {
				continue;
			}
			int collideOperand = findCollision(collect, newCollect, i);
			if (collideOperand >= 0) {
				noCollisions = false;
				if (warnalllocalcollisions) {
					reportWarning(ct.location,
						String.format(
							"Possible operand collision between symbols '%s' and '%s'",
							ct.getOperand(collideOperand).getName(), ct.getOperand(i).getName()));

				}
				break;	// Don't continue
			}
		}
		return noCollisions;
	}

	void checkLocalCollisions() {
		int collisionCount = 0;
		SubtableSymbol sym = root;	// Start with the instruction table
		int i = -1;
		for (;;) {
			int numconst = sym.getNumConstructors();
			for (int j = 0; j < numconst; ++j) {
				if (!checkLocalExports(sym.getConstructor(j))) {
					collisionCount += 1;
				}
			}
			i += 1;
			if (i >= tables.size()) {
				break;
			}
			sym = tables.get(i);
		}
		if (collisionCount > 0) {
			reportWarning(null,
				collisionCount + " constructors with local collisions between operands");
			if (!warnalllocalcollisions) {
				reportWarning(null, "Use -c switch to list each individually");
			}
		}
	}

	// Make sure label symbols are used properly
	String checkSymbols(SymbolScope scope) {
		entry("checkSymbols", scope);
		List<String> symbolErrors = new ArrayList<>();
		IteratorSTL<SleighSymbol> iter;
		for (iter = scope.begin(); !iter.equals(scope.end()); iter.increment()) {
			SleighSymbol sym = iter.get();
			if (sym.getType() != symbol_type.label_symbol) {
				continue;
			}
			LabelSymbol labsym = (LabelSymbol) sym;
			if (labsym.getRefCount() == 0) {
				symbolErrors.add(MessageFormattingUtils.format(labsym.location,
					String.format("Label <%s> was placed but never used", sym.getName())));
			}
			else if (!labsym.isPlaced()) {
				symbolErrors.add(MessageFormattingUtils.format(labsym.location,
					String.format("Label <%s> was referenced but never placed", sym.getName())));
			}
		}
		return symbolErrors.stream().collect(Collectors.joining("  "));
	}

	// Make sure symbol table errors are caught
	int addSymbol(SleighSymbol sym) {
		entry("addSymbol", sym);
		int id = -1;
		try {
			id = symtab.addSymbol(sym);
		}
		catch (SleighError err) {
			reportError(err.location, err.getMessage());
		}
		return id;
	}

	// public:
	public SleighCompile() {
		entry("SleighCompile");
		contextlock = false; // Context layout is not locked
		userop_count = 0;
		errors = 0;
		warnunnecessarypcode = false;
		lenientconflicterrors = true;
		warnallnops = false;
		root = null;
		pcode.resetLabelCount();
	}


	public void reportError(Location location, String msg) {
		entry("reportError", location, msg);
		Msg.error(this, MessageFormattingUtils.format(location, msg));

		errors += 1;
	}

	public void reportError(Location location, String msg, Throwable t) {
		entry("reportError", location, msg);
		Msg.error(this, MessageFormattingUtils.format(location, msg), t);

		errors += 1;
	}

	public void reportWarning(Location location, String msg) {
		entry("reportWarning", location, msg);
		Msg.warn(this, MessageFormattingUtils.format(location, msg));

		warnings += 1;
	}

	public void recordNop(Location location) {
		entry("recordNop", location);
		noplist.push_back("NOP detected at " + location);
	}

	public int numErrors() {
		entry("numErrors");
		return errors;
	}

	public int numWarnings() {
		entry("numWarnings");
		return warnings;
	}

	long getUniqueAddr() {
		entry("getUniqueAddr");
		long base = getUniqueBase();
		setUniqueBase(base + 16); // Should be maximum size of a unique
		return base;
	}

	void setUnnecessaryPcodeWarning(boolean val) {
		entry("setUnecessaryPcodeWarning", val);
		warnunnecessarypcode = val;
	}

	void setDeadTempWarning(boolean val) {
		entry("setDeadTempWarning", val);
		warndeadtemps = val;
	}

	void setUnusedFieldWarning(boolean val) {
		entry("setUnusedFieldWarning", val);
		warnunusedfields = val;
	}

	void setEnforceLocalKeyWord(boolean val) {
		entry("setEnforceLocalKeyWord", val);
		enforcelocalkeyword = val;
		pcode.setEnforceLocalKey(val);
	}

	void setLenientConflict(boolean val) {
		entry("setLenientConflict", val);
		lenientconflicterrors = val;
	}

	void setLocalCollisionWarning(boolean val) {
		entry("setLocalCollisionWarning", val);
		warnalllocalcollisions = val;
	}

	void setAllNopWarning(boolean val) {
		entry("setAllNopWarning", val);
		warnallnops = val;
	}

	// Do all post processing on the parsed data structures
	public void process() {
		entry("process");
		if (getDefaultSpace() == null) {
			reportError(null, "No default space specified");
		}
		if (errors > 0) {
			return;
		}
		checkConsistency();
		if (errors > 0) {
			return;
		}
		checkLocalCollisions();
		if (errors > 0) {
			return;
		}
		buildPatterns();
		if (errors > 0) {
			return;
		}
		buildDecisionTrees();
		if (errors > 0) {
			return;
		}
		ArrayList<SleighSymbol> errorPairs = new ArrayList<SleighSymbol>();
		buildXrefs(errorPairs);			// Make sure we can build crossrefs properly
		if (!errorPairs.isEmpty()) {
			for (int i = 0; i < errorPairs.size(); i += 2) {
				SleighSymbol sym1 = errorPairs.get(i);
				SleighSymbol sym2 = errorPairs.get(i + 1);
				String msg =
					String.format("Duplicate (offset,size) pair for registers: %s (%s) and %s (%s)",
						sym1.getName(), sym1.getLocation(), sym2.getName(), sym2.getLocation());

				reportError(sym1.getLocation(), msg);
				reportError(sym2.getLocation(), msg);
			}
			errors += 1;
			return;
		}
		checkUniqueAllocation();
		checkFieldUsage();
		symtab.purge(); // Get rid of any symbols we don't plan to save
	}

	// Lexer functions
	public void calcContextLayout() {
		entry("calcContextLayout");
		if (contextlock) {
			return; // Already locked
		}
		contextlock = true;

		int context_offset = 0;
		int begin, sz;
		contexttable.sort();
		begin = 0;
		while (begin < contexttable.size()) { // Define the context variables
			sz = 1;
			while ((begin + sz < contexttable.size()) &&
				(contexttable.get(begin + sz).sym.equals(contexttable.get(begin).sym))) {
				sz += 1;
			}
			context_offset = calcContextVarLayout(begin, sz, context_offset);
			begin += sz;
		}

		// context_size = (context_offset+8*sizeof(uintm)-1)/(8*sizeof(uintm));

		contexttable.clear();
	}

	private static final Pattern PREPROCPOS = Pattern.compile("%%%(.*)\b(\\d+)%%%");

	public void setPosition(String pos, int presumedLineno) {
		Matcher m;
		if ((m = PREPROCPOS.matcher(pos)).matches()) {
			filename = m.group(1);
			lineno = Integer.parseInt(m.group(2));
			this.linenoDifferential = lineno - presumedLineno;
		}
		else {
			throw new RuntimeException("couldn't parse position '" + pos + "'");
		}
	}

	public void setLineno(int presumedLineno) {
		lineno = presumedLineno + linenoDifferential;
	}

	Pair<Boolean, String> getPreprocValue(String nm) {
		IteratorSTL<Pair<String, String>> iter = preproc_defines.find(nm);
		if (iter.isEnd()) {
			return new Pair<>(false, null);
		}
		return new Pair<>(true, iter.get().second);
	}

	void setPreprocValue(String nm, String value) {
		preproc_defines.put(nm, value);
	}

	boolean undefinePreprocValue(String nm) {
		IteratorSTL<Pair<String, String>> iter = preproc_defines.find(nm);
		if (iter.isEnd()) {
			return false;
		}
		preproc_defines.erase(iter);
		return true;
	}

	// Parser functions
	public TokenSymbol defineToken(Location location, String name, long sz) {
		entry("defineToken", location, name, sz);
		int size = (int) sz;
		if ((size & 7) != 0) {
			reportError(location,
				"Definition of '" + name + "' token -- size must be multiple of 8");
			size = (size / 8) + 1;
		}
		else {
			size = size / 8;
		}
		ghidra.pcodeCPort.context.Token newtoken =
			new ghidra.pcodeCPort.context.Token(name, size, isBigEndian(), tokentable.size());
		tokentable.push_back(newtoken);
		TokenSymbol res = new TokenSymbol(location, newtoken);
		addSymbol(res);
		return res;
	}

	public void addTokenField(Location location, TokenSymbol sym, FieldQuality qual) {
		entry("addTokenField", location, sym, qual);
		TokenField field =
			new TokenField(location, sym.getToken(), qual.signext, qual.low, qual.high);
		addSymbol(new ValueSymbol(location, qual.name, field));
	}

	public boolean addContextField(VarnodeSymbol sym, FieldQuality qual) {
		entry("addContextField", sym, qual);
		if (contextlock) {
			return false; // Context layout has already been satisfied
		}

		contexttable.push_back(new FieldContext(sym, qual));
		return true;
	}

	private int bitsConsumedByUnitSize(int ws) {
		int cnt = 0;
		for (int test = ws - 1; test != 0; test >>= 1) {
			++cnt;
		}
		return cnt;
	}

	public void newSpace(Location location, SpaceQuality qual) {
		entry("newSpace", location, qual);
		if (qual.size == 0) {
			reportError(location, "Space definition '" + qual.name + "' missing size attribute");
			return;
		}

		if (qual.size <= 0 || qual.size > 8) {
			throw new SleighError("Space '" + qual.name + "' has unsupported size: " + qual.size,
				location);
		}
		if (qual.wordsize < 1 || qual.wordsize > 8) {
			throw new SleighError(
				"Space '" + qual.name + "' has unsupported wordsize: " + qual.wordsize, location);
		}
		int addressBits = bitsConsumedByUnitSize(qual.wordsize) + (8 * qual.size);
		if (addressBits > 64) {
			throw new SleighError(
				"Space '" + qual.name + "' has unsupported dimensions: requires " + addressBits +
					" bits -- limit is 64 bits",
				location);
		}

		int delay = (qual.type == space_class.register_space) ? 0 : 1;
		AddrSpace spc = new AddrSpace(this, spacetype.IPTR_PROCESSOR, qual.name, qual.size,
			qual.wordsize, numSpaces(), AddrSpace.hasphysical, delay);
		insertSpace(spc);
		if (qual.isdefault) {
			if (getDefaultSpace() != null) {
				reportError(location,
					"Multiple default spaces -- '" + getDefaultSpace().getName() + "', '" +
						qual.name + "'");
			}
			else {
				setDefaultSpace(spc.getIndex()); // Make the flagged space
				// the default
			}
		}
		addSymbol(new SpaceSymbol(location, spc));
	}

	// This MUST be called at the very beginning of the parse
	// The parser should enforce this
	public void setEndian(int end) {
		entry("setEndian", end);
		target_endian = end;
		predefinedSymbols(); // Set up symbols now that we know endianess
	}

	public void setAlignment(int val) {
		entry("setAlignment", val);
		alignment = val;
	}

	public void defineVarnodes(SpaceSymbol spacesym, long off, int size, VectorSTL<String> names,
			VectorSTL<Location> locations) {
		entry("defineVarnodes", spacesym, off, size, names, locations);
		AddrSpace spc = spacesym.getSpace();
		long myoff = off;
		for (int i = 0; i < names.size(); ++i) {
			Location location = locations.get(i);
			if (!"_".equals(names.get(i))) {
				addSymbol(new VarnodeSymbol(location, names.get(i), spc, myoff, size));
			}
			myoff += size;
		}
	}

	// Define a new symbol as a subrange of bits within another symbol
	// If the ends of the range fall on byte boundaries, we
	// simply define a normal VarnodeSymbol, otherwise we create
	// a special symbol which is a place holder for the bitrange operator
	public void defineBitrange(Location location, String name, VarnodeSymbol sym, int bitoffset,
			int numb) {
		entry("defineBitrange", location, name, sym, bitoffset, numb);
		String namecopy = name;
		int size = 8 * sym.getSize(); // Number of bits
		if (numb == 0) {
			reportError(location, "Size of bitrange is zero for '" + namecopy + "'");
			return;
		}
		if ((bitoffset >= size) || ((bitoffset + numb) > size)) {
			reportError(location, "Bad bitrange for '" + namecopy + "'");
			return;
		}
		if ((bitoffset % 8 == 0) && (numb % 8 == 0)) {
			// This can be reduced to an ordinary varnode definition
			AddrSpace newspace = sym.getFixedVarnode().space;
			long newoffset = sym.getFixedVarnode().offset;
			int newsize = numb / 8;
			if (isBigEndian()) {
				newoffset += (size - bitoffset - numb) / 8;
			}
			else {
				newoffset += bitoffset / 8;
			}
			addSymbol(new VarnodeSymbol(location, namecopy, newspace, newoffset, newsize));
		}
		else {
			if (size > 64) {
				reportError(location, "'" + sym.getName() + "': " +
					"Illegal bitrange on varnode larger than 64 bits");
			}
			// Otherwise define the special symbol
			addSymbol(new BitrangeSymbol(location, namecopy, sym, bitoffset, numb));
		}
	}

	public void addUserOp(VectorSTL<String> names, VectorSTL<Location> locations) {
		entry("addUserOp", names, locations);
		for (int i = 0; i < names.size(); ++i) {
			boolean isInternal = pcode.isInternalFunction(names.get(i));
			if (isInternal) {
				reportError(locations.get(i), "'" + names.get(i) +
					"' is an internal pcodeop and cannot be redefined as a pseudoop");
			}
			UserOpSymbol sym = new UserOpSymbol(locations.get(i), names.get(i));
			sym.setIndex(userop_count++);
			addSymbol(sym);
		}
	}

	// Find duplicates in -symlist-, null out all but first
	public SleighSymbol dedupSymbolList(VectorSTL<SleighSymbol> symlist) {
		entry("dedupSymbolList", symlist);
		SleighSymbol res = null;
		for (int i = 0; i < symlist.size(); ++i) {
			SleighSymbol sym = symlist.get(i);
			if (sym == null) {
				continue;
			}
			for (int j = i + 1; j < symlist.size(); ++j) {
				if (symlist.get(j) == sym) { // Found a duplicate
					// Return example duplicate for error reporting
					res = sym;
					// Null out the duplicate
					symlist.set(j, null);
				}
			}
		}
		return res;
	}

	public void attachValues(VectorSTL<SleighSymbol> symlist, VectorSTL<Location> locations,
			VectorSTL<Long> numlist) {
		entry("attachValues", symlist, locations, numlist);
		SleighSymbol dupsym = dedupSymbolList(symlist);
		if (dupsym != null) {
			reportWarning(dupsym.location,
				"'attach values' list contains duplicate entries: " + dupsym.getName());
		}
		for (int i = 0; i < symlist.size(); ++i) {
			Location location = locations.get(i);
			ValueSymbol sym = (ValueSymbol) symlist.get(i);
			if (sym == null) {
				continue;
			}
			PatternValue patval = sym.getPatternValue();
			if (patval.maxValue() + 1 != numlist.size()) {
				reportError(location,
					"Attach value '" + sym + "' is wrong size for list: " + numlist);
			}
			symtab.replaceSymbol(sym, new ValueMapSymbol(location, sym.getName(), patval, numlist));
		}
	}

	public void attachNames(VectorSTL<SleighSymbol> symlist, VectorSTL<Location> locations,
			VectorSTL<String> names) {
		entry("attachNames", symlist, locations, names);
		SleighSymbol dupsym = dedupSymbolList(symlist);
		if (dupsym != null) {
			reportWarning(dupsym.location,
				"'attach names' list contains duplicate entries: " + dupsym.getName());
		}
		for (int i = 0; i < symlist.size(); ++i) {
			Location location = locations.get(i);
			ValueSymbol sym = (ValueSymbol) symlist.get(i);
			if (sym == null) {
				continue;
			}
			PatternValue patval = sym.getPatternValue();
			if (patval.maxValue() + 1 != names.size()) {
				reportError(location, "Attach name '" + sym + "' is wrong size for list: " + names);
			}
			symtab.replaceSymbol(sym, new NameSymbol(location, sym.getName(), patval, names));
		}
	}

	public void attachVarnodes(VectorSTL<SleighSymbol> symlist, VectorSTL<Location> locations,
			VectorSTL<SleighSymbol> varlist) {
		entry("attachVarnodes", symlist, locations, varlist);
		SleighSymbol dupsym = dedupSymbolList(symlist);
		if (dupsym != null) {
			reportWarning(dupsym.location,
				"'attach variables' list contains duplicate entries: " + dupsym.getName());
		}
		for (int i = 0; i < symlist.size(); ++i) {
			Location location = locations.get(i);
			ValueSymbol sym = (ValueSymbol) symlist.get(i);
			if (sym == null) {
				continue;
			}
			if (firstContextField != null && sym.getId() == firstContextField) {
				reportError(location, "'" + sym.getName() + "'" +
					" cannot be used to attach variables because it occurs at the lowest bit position in context at " +
					sym.getLocation());
				continue;
			}
			PatternValue patval = sym.getPatternValue();
			if (patval.maxValue() + 1 != varlist.size()) {
				reportError(location,
					"Attach varnode '" + sym + "' is wrong size for list: " + varlist);
			}
			int sz = 0;
			for (int j = 0; j < varlist.size(); ++j) {
				VarnodeSymbol vsym = (VarnodeSymbol) varlist.get(j);
				if (vsym != null) {
					if (sz == 0) {
						sz = vsym.getFixedVarnode().size;
					}
					else if (sz != vsym.getFixedVarnode().size) {
						reportError(location,
							"Attach statement contains varnodes of different sizes");
						break;
					}
				}
			}
			symtab.replaceSymbol(sym,
				new VarnodeListSymbol(location, sym.getName(), patval, varlist));
		}
	}

	public SubtableSymbol newTable(Location location, String nm) {
		entry("newTable", location, nm);
		SubtableSymbol sym = new SubtableSymbol(location, nm);
		addSymbol(sym);
		tables.push_back(sym);
		return sym;
	}

	public void newOperand(Location location, Constructor ct, String nm) {
		entry("newOperand", location, ct, nm);
		int index = ct.getNumOperands();
		OperandSymbol sym = new OperandSymbol(location, nm, index, ct);
		addSymbol(sym);
		ct.addOperand(sym);
	}

	// Create constraint on operand
	public PatternEquation constrainOperand(Location location, OperandSymbol sym,
			PatternExpression patexp) {
		entry("constrainOperand", location, sym, patexp);
		PatternEquation res;
		TripleSymbol definingSymbol = sym.getDefiningSymbol();
		if (definingSymbol instanceof FamilySymbol) { // Operand already
			// defined as family symbol
			// This equation must be a constraint
			FamilySymbol famsym = (FamilySymbol) definingSymbol;
			res = new EqualEquation(location, famsym.getPatternValue(), patexp);
		}
		else { // Operand is currently undefined, so we can't constrain
			reportError(location, "Constraining currently undefined operand: " + sym);
			PatternExpression.release(patexp);
			res = null;
		}
		return res;
	}

	// Define operand in terms of PatternExpression
	public void defineOperand(Location location, OperandSymbol sym, PatternExpression patexp) {
		entry("defineOperand", location, sym, patexp);
		try {
			sym.defineOperand(patexp);
			sym.setOffsetIrrelevant(); // If not a self-definition, the operand
			// has no
			// pattern directly associated with it, so
			// the operand's offset is irrelevant
		}
		catch (SleighError err) {
			reportError(location, err.getMessage());
			PatternExpression.release(patexp);
		}
	}

	public PatternEquation defineInvisibleOperand(Location location, TripleSymbol sym) {
		entry("defineInvisibleOperand", location, sym);
		int index = curct.getNumOperands();
		OperandSymbol opsym = new OperandSymbol(location, sym.getName(), index, curct);
		addSymbol(opsym);
		curct.addInvisibleOperand(opsym);
		PatternEquation res = new OperandEquation(location, opsym.getIndex());
		symbol_type tp = sym.getType();
		try {
			if ((tp == symbol_type.value_symbol) || (tp == symbol_type.context_symbol)) {
				opsym.defineOperand(sym.getPatternExpression());
			}
			else {
				opsym.defineOperand(sym);
				// reportWarning("Defining invisible operand
				// "+sym.getName(),true);
			}
		}
		catch (SleighError err) {
			reportError(location, err.getMessage());
		}
		return res;
	}

	// Define operand as global symbol of same name
	public void selfDefine(OperandSymbol sym) {
		entry("selfDefine", sym);
		SleighSymbol sleighSymbol = symtab.findSymbol(sym.getName(), 1);
		if (!(sleighSymbol instanceof TripleSymbol)) {
			reportError(sym.getLocation(), "No matching global symbol '" + sym.getName() + "'");
			return;
		}
		TripleSymbol glob = (TripleSymbol) sleighSymbol;
		symbol_type tp = glob.getType();
		try {
			if ((tp == symbol_type.value_symbol) || (tp == symbol_type.context_symbol)) {
				sym.defineOperand(glob.getPatternExpression());
			}
			else {
				sym.defineOperand(glob);
			}
		}
		catch (SleighError err) {
			reportError(sym.getLocation(), err.getMessage());
		}
	}

	public boolean contextMod(VectorSTL<ContextChange> vec, ContextSymbol sym,
			PatternExpression pe) {
		entry("contextMod", vec, sym, pe);
		VectorSTL<PatternValue> vallist = new VectorSTL<>();
		pe.listValues(vallist);
		for (int i = 0; i < vallist.size(); ++i) {
			if (vallist.get(i) instanceof EndInstructionValue) {
				return false;
			}
		}

		ContextField field = (ContextField) sym.getPatternValue();
		ContextOp op = new ContextOp(sym.getLocation(), field.getStartBit(), field.getEndBit(), pe);
		vec.push_back(op);
		return true;
	}

	public void contextSet(VectorSTL<ContextChange> vec, TripleSymbol sym, ContextSymbol cvar) {
		entry("contextSet", vec, sym, cvar);
		ContextField field = (ContextField) cvar.getPatternValue();
		ContextCommit op =
			new ContextCommit(sym, field.getStartBit(), field.getEndBit(), cvar.isFlow());
		vec.push_back(op);
	}

	// create a macro symbol (with parameter names)
	public MacroSymbol createMacro(Location location, String name, VectorSTL<String> params,
			VectorSTL<Location> locations) {
		entry("createMacro", location, name, params, locations);
		curct = null; // Not currently defining a Constructor
		curmacro = new MacroSymbol(location, name, macrotable.size());
		addSymbol(curmacro);
		symtab.addScope(); // New scope for the body of the macro definition
		pcode.resetLabelCount(); // Macros have their own labels
		for (int i = 0; i < params.size(); ++i) {
			OperandSymbol oper = new OperandSymbol(locations.get(i), params.get(i), i, null);
			addSymbol(oper);
			curmacro.addOperand(oper);
		}
		return curmacro;
	}

	// Match up any qualities of the macro's OperandSymbols with
	// any OperandSymbol passed into the macro
	void compareMacroParams(MacroSymbol sym, VectorSTL<ExprTree> param) {
		entry("compareMacroParams", sym, param);
		for (int i = 0; i < param.size(); ++i) {
			VarnodeTpl outvn = param.get(i).outvn;
			if (outvn == null) {
				continue;
			}
			// Check if an OperandSymbol was passed into this macro
			if (outvn.getOffset().getType() != ConstTpl.const_type.handle) {
				continue;
			}
			int hand = outvn.getOffset().getHandleIndex();

			// The matching operands
			OperandSymbol macroop = sym.getOperand(i);
			OperandSymbol parentop;
			if (curct == null) {
				parentop = curmacro.getOperand(hand);
			}
			else {
				parentop = curct.getOperand(hand);
			}

			// This is the only property we check right now
			if (macroop.isCodeAddress()) {
				parentop.setCodeAddress();
			}
		}
	}

	// Create macro build directive, given symbol and parameters
	public VectorSTL<OpTpl> createMacroUse(Location location, MacroSymbol sym,
			VectorSTL<ExprTree> param) {
		entry("createMacroUse", location, sym, param);
		if (sym.getNumOperands() != param.size()) {
			boolean tooManyParams = param.size() > sym.getNumOperands();
			reportError(sym.getLocation(), String.format("Invocation of macro '%s' passes too " +
				(tooManyParams ? "many" : "few") + " parameters", sym.getName()));

			return new VectorSTL<>();
		}
		compareMacroParams(sym, param);
		OpTpl op = new OpTpl(location, OpCode.CPUI_CAST);
		VarnodeTpl idvn = new VarnodeTpl(location, new ConstTpl(getConstantSpace()),
			new ConstTpl(ConstTpl.const_type.real, sym.getIndex()),
			new ConstTpl(ConstTpl.const_type.real, 4));
		op.addInput(idvn);
		return ExprTree.appendParams(op, param);
	}

	public Constructor createConstructor(Location location, SubtableSymbol sym) {
		entry("createConstructor", location, sym);
		if (sym == null) {
			sym = WithBlock.getCurrentSubtable(withstack);
		}
		if (sym == null) { // still
			sym = root;
		}
		curmacro = null; // Not currently defining a macro
		curct = new Constructor(location, sym);
		sym.addConstructor(curct);
		symtab.addScope(); // Make a new symbol scope for our constructor
		pcode.resetLabelCount();
		return curct;
	}

	// Reset set state after a an error in previous constructor
	void resetConstructors() {
		entry("resetConstructors");
		symtab.setCurrentScope(symtab.getGlobalScope()); // Purge any
		// dangling local
		// scopes
	}

	// Find a defining instance of the local variable
	// with given -offset-
	private static VarnodeTpl find_size(ConstTpl offset, ConstructTpl ct) {
		entry("find_size", offset, ct);
		VectorSTL<OpTpl> ops = ct.getOpvec();
		VarnodeTpl vn;
		OpTpl op;

		for (int i = 0; i < ops.size(); ++i) {
			op = ops.get(i);
			vn = op.getOut();
			if ((vn != null) && (vn.isLocalTemp())) {
				if (vn.getOffset().equals(offset)) {
					return vn;
				}
			}
			for (int j = 0; j < op.numInput(); ++j) {
				vn = op.getIn(j);
				if (vn.isLocalTemp() && (vn.getOffset().equals(offset))) {
					return vn;
				}
			}
		}
		return null;
	}

	// Look for zero size temps in export statement
	private static boolean force_exportsize(ConstructTpl ct) {
		entry("force_exportsize", ct);
		HandleTpl result = ct.getResult();
		if (result == null) {
			return true;
		}

		VarnodeTpl vt;

		if (result.getPtrSpace().isUniqueSpace() && result.getPtrSize().isZero()) {
			vt = find_size(result.getPtrOffset(), ct);
			if (vt == null) {
				return false;
			}
			result.setPtrSize(vt.getSize());
		}
		else if (result.getSpace().isUniqueSpace() && result.getSize().isZero()) {
			vt = find_size(result.getPtrOffset(), ct);
			if (vt == null) {
				return false;
			}
			result.setSize(vt.getSize());
		}
		return true;
	}

	boolean expandMacros(ConstructTpl ctpl) {
		VectorSTL<OpTpl> vec = ctpl.getOpvec();
		VectorSTL<OpTpl> newvec = new VectorSTL<>();
		IteratorSTL<OpTpl> iter;
		for (iter = vec.begin(); !iter.isEnd(); iter.increment()) {
			OpTpl op = iter.get();
			if (op.getOpcode() == OpCode.CPUI_CAST) {
				MacroBuilder builder =
					new MacroBuilder(this, op.location, newvec, ctpl.numLabels());
				int index = (int) op.getIn(0).getOffset().getReal();
				if (index >= macrotable.size()) {
					return false;
				}
				builder.setMacroOp(op);
				ConstructTpl macro_tpl = macrotable.get(index);
				builder.build(macro_tpl, -1);
				ctpl.setNumLabels(ctpl.numLabels() + macro_tpl.numLabels());
				op.dispose(); // Throw away the place holder op
				if (builder.hasError()) {
					return false;
				}
			}
			else {
				newvec.push_back(op);
			}
		}
		ctpl.setOpvec(newvec);
		return true;
	}

	boolean finalizeSections(Constructor big, SectionVector vec) {
		entry("finalizeSections", big, vec);
		// Do all final checks, expansions, and linking for p-code sections
		VectorSTL<String> myErrors = new VectorSTL<>();

		RtlPair cur = vec.getMainPair();
		int i = -1;
		String sectionstring = "   Main section: ";
		int max = vec.getMaxId();
		for (;;) {

			String scopeString = cur.section.loc + ": " + sectionstring;

			String errstring;

			errstring = checkSymbols(cur.scope); // Check labels in the section's scope
			if (errstring.length() != 0) {
				myErrors.push_back(scopeString + errstring);
			}
			else {
				if (!expandMacros(cur.section)) {
					myErrors.push_back(scopeString + "Could not expand macros");
				}
				VectorSTL<Integer> check = new VectorSTL<>();
				big.markSubtableOperands(check);
				Pair<Integer, Location> res = cur.section.fillinBuild(check, getConstantSpace());
				if (res.first == 1) {
					myErrors.push_back(
						scopeString + "Duplicate BUILD statements at " + res.second);
				}
				if (res.first == 2) {
					myErrors.push_back(
						scopeString + "Unnecessary BUILD statements at " + res.second);
				}

				if (!pcode.propagateSize(cur.section)) {
					myErrors.push_back(
						scopeString + "Could not resolve at least 1 variable size");
				}
			}
			if (i < 0) {		// These potential errors only apply to main section
				if (cur.section.getResult() != null) {	// If there is an export statement
					if (big.getParent() == root) {
						myErrors.push_back("   Cannot have export statement in root constructor");
					}
					else if (!force_exportsize(cur.section)) {
						myErrors.push_back("   Size of export is unknown");
					}
				}
			}
			if (cur.section.delaySlot() != 0) { // Delay slot is present in this constructor
				if (root != big.getParent()) { // it is not in a root constructor
					reportWarning(big.location, "Delay slot used in " + big);
				}
				if (cur.section.delaySlot() > maxdelayslotbytes) {
					maxdelayslotbytes = cur.section.delaySlot();
				}
			}
			do {
				i += 1;
				if (i >= max) {
					break;
				}
				cur = vec.getNamedPair(i);
			}
			while (cur.section == null);

			if (i >= max) {
				break;
			}
			SectionSymbol sym = sections.get(i);
			sectionstring = "   " + sym.getName() + " section: ";
		}
		if (!myErrors.empty()) {
			reportError(big.location, "in " + big);
			for (int j = 0; j < myErrors.size(); ++j) {
				reportError(big.location, myErrors.get(j));
			}
			return false;
		}
		return true;
	}

	void shiftUniqueVn(VarnodeTpl vn, int sa) {
		entry("shiftUniqueVn", vn, sa);
		// If the varnode is in the unique space, shift its offset up by -sa- bits
		if (vn.getSpace().isUniqueSpace() &&
			(vn.getOffset().getType() == ConstTpl.const_type.real)) {
			long val = vn.getOffset().getReal();
			val <<= sa;
			vn.setOffset(val);
		}
	}

	void shiftUniqueOp(OpTpl op, int sa) {
		entry("shiftUniqueOp", op, sa);
		// Shift the offset up by -sa- bits for any varnode used by this -op- in the unique space
		VarnodeTpl outvn = op.getOut();
		if (outvn != null) {
			shiftUniqueVn(outvn, sa);
		}
		for (int i = 0; i < op.numInput(); ++i) {
			shiftUniqueVn(op.getIn(i), sa);
		}
	}

	void shiftUniqueHandle(HandleTpl hand, int sa) {
		entry("shiftUniqueHandle", hand, sa);
		// Shift the offset up by -sa- bits, for either the dynamic or static varnode aspects that are in the unique space
		if (hand.getSpace().isUniqueSpace() &&
			(hand.getPtrSpace().getType() == ConstTpl.const_type.real) &&
			(hand.getPtrOffset().getType() == ConstTpl.const_type.real)) {
			long val = hand.getPtrOffset().getReal();
			val <<= sa;
			hand.setPtrOffset(val);
		}
		else if (hand.getPtrSpace().isUniqueSpace() &&
			(hand.getPtrOffset().getType() == ConstTpl.const_type.real)) {
			long val = hand.getPtrOffset().getReal();
			val <<= sa;
			hand.setPtrOffset(val);
		}

		if (hand.getTempSpace().isUniqueSpace() &&
			(hand.getTempOffset().getType() == ConstTpl.const_type.real)) {
			long val = hand.getTempOffset().getReal();
			val <<= sa;
			hand.setTempOffset(val);
		}
	}

	void shiftUniqueConstruct(ConstructTpl tpl, int sa) {
		entry("shiftUniqueConstruct", tpl, sa);
		// Shift the offset up by -sa- bits, for any varnode in the unique space associated with this template
		HandleTpl result = tpl.getResult();
		if (result != null) {
			shiftUniqueHandle(result, sa);
		}
		VectorSTL<OpTpl> vec = tpl.getOpvec();
		for (int i = 0; i < vec.size(); ++i) {
			shiftUniqueOp(vec.get(i), sa);
		}
	}

	void checkUniqueAllocation() {
		// With crossbuilds,  temporaries may need to survive across instructions in a packet, so here we
		// provide space in the offset of the temporary (within the unique space) so that the run-time sleigh
		// engine can alter the value to prevent collisions with other nearby instructions
		if (unique_allocatemask == 0) {
			return;	// We don't have any crossbuild directives
		}

		unique_allocatemask = 0xff;	// Provide 8 bits of free space
		int sa = 8;
		int secsize = sections.size(); // This is the upper bound for section numbers
		SubtableSymbol sym = root; // Start with the instruction table
		int i = -1;
		for (;;) {
			int numconst = sym.getNumConstructors();
			for (int j = 0; j < numconst; ++j) {
				Constructor ct = sym.getConstructor(j);
				ConstructTpl tpl = ct.getTempl();
				if (tpl != null) {
					shiftUniqueConstruct(tpl, sa);
				}
				for (int k = 0; k < secsize; ++k) {
					ConstructTpl namedtpl = ct.getNamedTempl(k);
					if (namedtpl != null) {
						shiftUniqueConstruct(namedtpl, sa);
					}
				}
			}
			i += 1;
			if (i >= tables.size()) {
				break;
			}
			sym = tables.get(i);
		}
		long ubase = getUniqueBase(); // We have to adjust the unique base
		ubase <<= sa;
		setUniqueBase(ubase);
	}

	void checkFieldUsage() {
		if (warnunusedfields) {
			VectorSTL<SleighSymbol> unsoughtSymbols = symtab.getUnsoughtSymbols();
			IteratorSTL<SleighSymbol> siter;
			for (siter = unsoughtSymbols.begin(); !siter.isEnd(); siter.increment()) {
				SleighSymbol sleighSymbol = siter.get();
				if (sleighSymbol instanceof ValueSymbol) {
					ValueSymbol valueSymbol = (ValueSymbol) sleighSymbol;
					PatternValue patternValue = valueSymbol.getPatternValue();
					if (patternValue instanceof TokenField) {
						if (sleighSymbol.location != Location.INTERNALLY_DEFINED) {
							reportWarning(patternValue.location, "token field '" +
								sleighSymbol.getName() + "' defined but never used");
						}
					}
				}
			}
		}
	}

	public void pushWith(SubtableSymbol ss, PatternEquation pateq,
			VectorSTL<ContextChange> contvec) {
		withstack.push(new WithBlock(ss, pateq, contvec));
	}

	public void popWith() {
		withstack.pop();
	}

	public void buildConstructor(Constructor big, PatternEquation pateq,
			VectorSTL<ContextChange> contvec, SectionVector vec) {
		// Take all the different parse pieces for a Constructor and build the Constructor object
		boolean noerrors = true;
		if (vec != null) { // If the sections were implemented
			noerrors = finalizeSections(big, vec);
			if (noerrors) {		// Attach the sections to the Constructor
				big.setMainSection(vec.getMainSection());
				int max = vec.getMaxId();
				for (int i = 0; i < max; ++i) {
					ConstructTpl section = vec.getNamedSection(i);
					if (section != null) {
						big.setNamedSection(section, i);
					}
				}
			}
		}
		if (noerrors) {
			pateq = WithBlock.collectAndPrependPattern(withstack, pateq);
			contvec = WithBlock.collectAndPrependContext(withstack, contvec);
			big.addEquation(pateq);
			big.removeTrailingSpace();
			if (contvec != null) {
				big.addContext(contvec);
//	      delete contvec;
			}
		}
		symtab.popScope();		// In all cases pop scope
//	  delete vec;
	}

	public void buildMacro(MacroSymbol sym, ConstructTpl rtl) {
		entry("buildMacro", sym, rtl);
		String errstring = checkSymbols(symtab.getCurrentScope());
		if (errstring.length() != 0) {
			reportError(sym.getLocation(),
				"Error in definition of macro '" + sym.getName() + "': " + errstring);
			return;
		}
		if (!expandMacros(rtl)) {
			reportError(sym.getLocation(),
				"Could not expand submacro in definition of macro '" + sym.getName() + "'");
			return;
		}
		pcode.propagateSize(rtl); // Propagate size information (as much as possible)
		sym.setConstruct(rtl);
		symtab.popScope(); // Pop local variables used to define macro
		macrotable.push_back(rtl);
	}

	// Virtual functions (not used by the compiler)
	@Override
	public void initialize(DocumentStorage store) {
		// do nothing
	}

	@Override
	public int instructionLength(Address baseaddr) {
		return 0;
	}

	@Override
	public int printAssembly(PrintStream s, int size, Address baseaddr) {
		return 0;
	}

	/**
	 * Run the sleigh compiler.  This provides a direct means of invoking the
	 * compiler without using the launcher.  The full SoftwareModeling classpath 
	 * must be established including any dependencies.
	 * @param args compiler command line arguments
	 * @throws JDOMException for XML errors
	 * @throws IOException for file access errors
	 * @throws RecognitionException for parsing errors
	 */
	public static void main(String[] args) throws JDOMException, IOException, RecognitionException {
		System.exit(SleighCompileLauncher.runMain(args));
	}
}
