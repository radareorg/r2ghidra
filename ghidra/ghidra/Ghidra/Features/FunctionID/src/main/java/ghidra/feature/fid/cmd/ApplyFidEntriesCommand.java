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
package ghidra.feature.fid.cmd;

import java.io.IOException;
import java.util.*;

import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.feature.fid.db.FidQueryService;
import ghidra.feature.fid.service.*;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class ApplyFidEntriesCommand extends BackgroundCommand {
	public static final String FID_CONFLICT = "FID_conflict:";
	public static final String FID_BOOKMARK_CATEGORY = "Function ID Analyzer";
	public static final String FIDCONFLICT_BOOKMARK_CATEGORY = "Function ID Conflict";
	public static final int MAGIC_MULTIPLE_MATCH_LIMIT = 10;
	public static final int MAGIC_MULTIPLE_LIBRARY_LIMIT = 5;
	public static final int MAX_PLATE_COMMENT_LINE_LENGTH = 58;

	private MatchNameAnalysis nameAnalysis = new MatchNameAnalysis();
	private AddressSet affectedLocations = new AddressSet();
	private TreeMap<String, Address> multiMatchNames = new TreeMap<String, Address>();
	private LinkedList<Address> conflictFunctions = new LinkedList<Address>();
	private boolean alwaysApplyFidLabels;
	private float scoreThreshold;
	private float multiNameScoreThreshold;
	private boolean createBookmarksEnabled;

	public ApplyFidEntriesCommand(AddressSetView set, float scoreThreshold, float multiThreshold,
			boolean alwaysApplyFidLabels, boolean createBookmarksEnabled) {
		super("ApplyFidEntriesCommand", true, true, false);
		this.scoreThreshold = scoreThreshold;
		this.multiNameScoreThreshold = multiThreshold;
		this.alwaysApplyFidLabels = alwaysApplyFidLabels;
		this.createBookmarksEnabled = createBookmarksEnabled;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		FidService service = new FidService();

		if (obj instanceof Program) {
			Program program = (Program) obj;

			if (!service.canProcess(program.getLanguage())) {
				return false;
			}

			try (FidQueryService fidQueryService =
				service.openFidQueryService(program.getLanguage(), false)) {

				monitor.setMessage("FID Analysis");
				List<FidSearchResult> processProgram =
					service.processProgram(program, fidQueryService, scoreThreshold, monitor);
				if (processProgram == null) {
					return false;
				}

				for (FidSearchResult entry : processProgram) {
					monitor.checkCanceled();

					monitor.incrementProgress(1);
					if (entry.function.isThunk()) {
						continue;
					}

					if (!entry.matches.isEmpty()) {
						processMatches(entry, program, monitor);
					}
					else {
						Msg.trace(this, "no results for function " + entry.function.getName() +
							" at " + entry.function.getEntryPoint());
					}
				}
				applyConflictLabels(program);
			}
			catch (CancelledException e) {
				return false;
			}
			catch (VersionException | IOException e) {
				setStatusMsg(e.getMessage());
				return false;
			}

			return true;
		}
		return false;
	}

	private void processMatches(FidSearchResult result, Program program, TaskMonitor monitor)
			throws CancelledException {
		String bookmarkContents = null;
		String plateCommentContents = null;

		if (result.matches.size() == 0) {
			// nothing to do - eliminate functions above might have removed all possibilities
			return;
		}

		nameAnalysis.analyzeNames(result.matches, program, monitor);
		if (nameAnalysis.getMostOptimisticCount() > 1) { // If we can't narrow down to a single name
			if (nameAnalysis.getOverallScore() < multiNameScoreThreshold) {
				return;
			}
		}
		nameAnalysis.analyzeLibraries(result.matches, MAGIC_MULTIPLE_LIBRARY_LIMIT, monitor);

		String newFunctionName = null;
		if (nameAnalysis.numNames() == 1) {
			newFunctionName = nameAnalysis.getNameIterator().next();
		}

		if (nameAnalysis.numSimilarNames() == 1) { // If all names are the same, up to a difference in '_' prefix
			bookmarkContents = "Library Function - Single Match, ";
			plateCommentContents = "Library Function - Single Match";
		}
		else { // If names are different in some way
			bookmarkContents = "Library Function - Multiple Matches, ";
			plateCommentContents = "Library Function - Multiple Matches";
			if (nameAnalysis.numNames() == 1) {
				plateCommentContents = plateCommentContents + " With Same Base Name";
				bookmarkContents = bookmarkContents + "Same ";
			}
			else {
				plateCommentContents = plateCommentContents + " With Different Base Names";
				bookmarkContents = bookmarkContents + "Different ";
			}
		}
		// multiple matches - TODO: change to show classes vs libraries - libraries with same name don't put "base" name only for class ones

		plateCommentContents = generateComment(plateCommentContents, monitor);
		bookmarkContents = generateBookmark(bookmarkContents);

		applyMarkup(result.function, newFunctionName, plateCommentContents, bookmarkContents,
			monitor);
	}

	private String listNames(TaskMonitor monitor) throws CancelledException {
		StringBuilder buffer = new StringBuilder();

		int counter = 0;

		Iterator<String> iterator = nameAnalysis.getNameIterator();
		while (iterator.hasNext()) {
			monitor.checkCanceled();
			buffer.append(' ');
			buffer.append(iterator.next());
			buffer.append('\n');
			counter++;
			if (counter > 3) {
				break;
			}
		}
		if (iterator.hasNext()) {
			buffer.append("  " + nameAnalysis.numNames() + " names - too many to list\n");
		}

		return buffer.toString();
	}

	private String listLibraries(TaskMonitor monitor) throws CancelledException {
		StringBuilder buffer = new StringBuilder();

		if (nameAnalysis.numLibraries() == 1) {
			buffer.append("Library: ");
		}
		else {
			buffer.append("Libraries: ");
		}
		int counter = 0;

		if (nameAnalysis.numLibraries() < MAGIC_MULTIPLE_LIBRARY_LIMIT) {
			Iterator<String> iterator = nameAnalysis.getLibraryIterator();
			while (iterator.hasNext()) {
				monitor.checkCanceled();
				if (counter != 0) {
					buffer.append(", ");
				}
				buffer.append(iterator.next());
				counter++;
			}
		}
		else {
			buffer.append(nameAnalysis.numLibraries() + " - too many to list");
		}

		return buffer.toString();
	}

	private String generateComment(String header, TaskMonitor monitor) throws CancelledException {
		StringBuilder buffer = new StringBuilder();
		buffer.append(header);

		// append names, class, and library info buffer
		buffer.append("\n");
		buffer.append(listNames(monitor));
		buffer.append("\n");
		buffer.append(listLibraries(monitor));

		return buffer.toString();
	}

	private String generateBookmark(String bookmark) {
		StringBuilder buffer = new StringBuilder();
		if (createBookmarksEnabled) {
			buffer.append(bookmark);

			buffer.append(" ");
			buffer.append(nameAnalysis.getNameIterator().next());
		}

		return buffer.toString();
	}

	private void applyMarkup(Function function, String newFunctionName, String plateCommentContents,
			String bookmarkContents, TaskMonitor monitor) throws CancelledException {

		// don't need to apply fid unless there are no "good" symbols or the option is set to always do it.
		if (!alwaysApplyFidLabels && hasUserOrImportedSymbols(function)) {
			return;
		}

		// single name case ok
		if (newFunctionName != null) {
			addFunctionLabel(function, newFunctionName, monitor);
		}
		// multiple names
		else {
			addFunctionLabelMultipleMatches(function, monitor);
		}
		if (plateCommentContents != null && !plateCommentContents.equals("")) {
			function.setComment(plateCommentContents);
		}
		if (bookmarkContents != null && !bookmarkContents.equals("")) {
			function.getProgram()
					.getBookmarkManager()
					.setBookmark(function.getEntryPoint(),
						BookmarkType.ANALYSIS, FID_BOOKMARK_CATEGORY, bookmarkContents);
		}
	}

	/**
	 * Returns true if there are symbol names at the function entry point that were either
	 * created by a user or an importer. (i.e trusted)
	 * @param function the function to test for trusted symbols
	 * @return true if there are symbol names at the function entry point that were either
	 */
	private boolean hasUserOrImportedSymbols(Function function) {
		Program program = function.getProgram();
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol[] symbols = symbolTable.getSymbols(function.getEntryPoint());
		for (Symbol symbol : symbols) {
			SourceType sourceType = symbol.getSource();
			if (sourceType == SourceType.USER_DEFINED || sourceType == SourceType.IMPORTED) {
				return true;
			}
		}
		return false;
	}

	private void addFunctionLabel(Function function, String newFunctionName, TaskMonitor monitor) {

		removeConflictSymbols(function, newFunctionName, monitor);

		//now add the unique symbol name to the matched function - could have done this before deduping but would have to check for it and ignore it - easier to do later
		addSymbolToFunction(function, newFunctionName);
	}

	/**
	 * Delete a symbol of the given name and address, knowing there are multiple Symbols at the address.
	 * If the symbol is primary, make another Symbol at the address primary before deleting
	 * @param matchName is the given Symbol name
	 * @param addr is the given Address
	 * @param program is the Program
	 * @return the number of Symbols remaining at the address
	 */
	private int deleteSymbol(String matchName, Address addr, Program program) {
		int numSymbols = 0;
		for (int i = 0; i < 2; ++i) {	// Try to find non-primary matching Symbol at most twice
			Symbol[] symbols = program.getSymbolTable().getSymbols(addr);
			numSymbols = symbols.length;
			if (numSymbols <= 1) {
				break;
			}
			for (Symbol sym : symbols) {		// Among Symbols at the Address
				if (sym.getName().equals(matchName)) {	// Find one with matching name
					if (!sym.isPrimary()) {		// If it is not primary
						sym.delete();			// delete it immediately
						numSymbols -= 1;
						break;					// and we are done
					}
					Symbol otherSym = symbols[0];
					if (otherSym == sym) {		// Otherwise find another Symbol, which must not be primary
						otherSym = symbols[1];
					}
					// Set the other symbol to primary
					SetLabelPrimaryCmd cmd = new SetLabelPrimaryCmd(addr, otherSym.getName(),
						otherSym.getParentNamespace());
					cmd.applyTo(program);
					break;
				}
			}
		}
		return numSymbols;
	}

	// This is called when a single library match is made. It checks to see if the label of the single match is contained in
	// the set of "FID conflict" functions with multiple matches.
	// If it is, that label is removed from the other function(s) since it is no longer a possibility.
	// Also checks those locations to see if there is only one label left and if so, removes the "FID conflict" bookmark.
	private void removeConflictSymbols(Function function, String matchName, TaskMonitor monitor) {

		Address addr = multiMatchNames.get(matchName);
		if (addr == null) {
			return;
		}
		Program program = function.getProgram();
		int numSymbols = deleteSymbol(matchName, addr, program);
		if (numSymbols <= 1) {
			// Only one symbol left, delete the "FID conflict" bookmark
			BookmarkManager bookmarkManager = program.getBookmarkManager();
			Bookmark bookmark = bookmarkManager.getBookmark(addr, BookmarkType.ANALYSIS,
				FIDCONFLICT_BOOKMARK_CATEGORY);
			if (bookmark != null) {
				bookmarkManager.removeBookmark(bookmark);
			}
		}
	}

	private int addFunctionLabelMultipleMatches(Function function, TaskMonitor monitor)
			throws CancelledException {

		Program program = function.getProgram();

		if (nameAnalysis.numNames() >= MAGIC_MULTIPLE_MATCH_LIMIT) {
			return nameAnalysis.numNames();
		}

		Symbol symbol = function.getSymbol();
		boolean preexistingSymbol = (symbol != null && symbol.getSource() != SourceType.DEFAULT);

		Set<String> unusedNames =
			getFIDNamesThatDontExistSomewhereElse(program, nameAnalysis.getNameIterator());

		Address addr = function.getEntryPoint();
		for (String functionName : unusedNames) {
			monitor.checkCanceled();
			addSymbolToFunction(function, functionName);
			multiMatchNames.put(functionName, addr);
		}

		if (unusedNames.size() > 1) {
			if (!preexistingSymbol) {
				conflictFunctions.add(addr);
			}
			if (createBookmarksEnabled) {
				BookmarkManager bookmarkManager = function.getProgram().getBookmarkManager();
				bookmarkManager.setBookmark(addr, BookmarkType.ANALYSIS,
					FIDCONFLICT_BOOKMARK_CATEGORY,
				"Multiple likely matching functions");
			}
		}
		return unusedNames.size();
	}

	/**
	 * Apply special FID_CONFLICT to the primary symbol on functions where we had multiple matches
	 * @param program is the Program
	 */
	private void applyConflictLabels(Program program) {
		SymbolTable symbolTable = program.getSymbolTable();
		for (Address addr : conflictFunctions) {
			Symbol[] symbols = symbolTable.getSymbols(addr);
			if (symbols.length <= 1) {
				continue;		// Only apply conflict label if more than one symbol at address
			}
			Symbol symbol = null;
			for (Symbol symbol2 : symbols) {
				if (symbol2.isPrimary()) {
					symbol = symbol2;
					break;
				}
			}
			if (symbol == null || !symbol.isGlobal()) {
				continue;
			}
			String baseName = symbol.getName();
			if (baseName.startsWith(FID_CONFLICT)) {
				continue;		// Conflict label previously applied
			}
			DemangledObject demangle = NameVersions.demangle(program, baseName);
			if (demangle != null) {
				baseName = demangle.getName();
			}
			baseName = FID_CONFLICT + baseName;
			try {
				symbol = symbolTable.createLabel(addr, baseName, null, SourceType.ANALYSIS);
				SetLabelPrimaryCmd cmd =
					new SetLabelPrimaryCmd(addr, symbol.getName(), symbol.getParentNamespace());
				cmd.applyTo(program);
			}
			catch (InvalidInputException e) {
				Msg.warn(SymbolUtilities.class,
					"Invalid symbol name: \"" + baseName + "\" at " + addr);
			}
		}
	}

	/**
	 * Takes a set of FID matching names and returns a subset that includes only names that don't exist
	 * somewhere else in the program.
	 */
	private static Set<String> getFIDNamesThatDontExistSomewhereElse(Program program,
			Iterator<String> iter) {

		Set<String> unusedNames = new HashSet<String>();
		SymbolTable symbolTable = program.getSymbolTable();
		while (iter.hasNext()) {
			String name = iter.next();
			if (!nameExistsSomewhereElse(symbolTable, name)) {
				unusedNames.add(name);
			}
		}
		return unusedNames;
	}

	//Check to see if other functions exist with the same baseName or _baseName or __baseName
	private static boolean nameExistsSomewhereElse(SymbolTable symTab, String baseName) {

		//I did it this way because doing it with an iterator and wildcard was really really slow
		List<Symbol> globalSymbols = symTab.getLabelOrFunctionSymbols(baseName, null);
		if (!globalSymbols.isEmpty()) {
			return true;
		}

		globalSymbols = symTab.getLabelOrFunctionSymbols("_" + baseName, null);
		if (!globalSymbols.isEmpty()) {
			return true;
		}

		globalSymbols = symTab.getLabelOrFunctionSymbols("__" + baseName, null);
		if (!globalSymbols.isEmpty()) {
			return true;
		}

		return false;
	}

	private void addSymbolToFunction(Function function, String name) {
		SymbolTable symbolTable = function.getProgram().getSymbolTable();
		Address address = function.getEntryPoint();
		try {
			symbolTable.createLabel(address, name, null, SourceType.ANALYSIS);
			affectedLocations.add(address);
		}
		catch (InvalidInputException e) {
			Msg.warn(SymbolUtilities.class, "Invalid symbol name: \"" + name + "\" at " + address);
		}
	}

	public AddressSetView getFIDLocations() {
		return new AddressSetViewAdapter(affectedLocations);
	}

}
