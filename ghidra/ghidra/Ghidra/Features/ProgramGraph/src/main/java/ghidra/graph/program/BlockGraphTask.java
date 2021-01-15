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
package ghidra.graph.program;

import java.awt.Color;
import java.util.*;

import docking.widgets.EventTrigger;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.service.graph.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * <CODE>GraphTask</CODE> is a threaded task creating either a block or call graph.
 */
public class BlockGraphTask extends Task {

	private static final String CODE_ATTRIBUTE = "Code";
	private static final String SYMBOLS_ATTRIBUTE = "Symbols";

	protected static final String PROGRESS_DIALOG_TITLE = "Graphing Program";
	protected static final String INIT_PROGRESS_MSG = "Graphing Program...";

	private boolean graphEntryPointNexus = false;
	private boolean showCode = false;
	private int codeLimitPerBlock = 10;

	private ColorizingService colorizingService;

	/**
	 * Edge flow tags
	 */
	protected final static int FALLTHROUGH = 0;
	protected final static int CONDITIONAL_RETURN = 1;
	protected final static int UNCONDITIONAL_JUMP = 2;
	protected final static int CONDITIONAL_JUMP = 3;
	protected final static int UNCONDITIONAL_CALL = 4;
	protected final static int CONDITIONAL_CALL = 5;
	protected final static int TERMINATOR = 6;
	protected final static int COMPUTED = 7;
	protected final static int INDIRECTION = 8;
	protected final static int ENTRY = 9; // from Entry Nexus

	protected final static String[] edgeNames =
		{ "1", "2", "3", "4", "5", "6", "7", "13", "14", "15" };

	// @formatter:off
	protected final static String[] edgeTypes = {
			"Fall-Through",
			"Conditional-Return",
			"Unconditional-Jump",
			"Conditional-Jump",
			"Unconditional-Call",
			"Conditional-Call",
			"Terminator",
			"Computed",
			"Indirection",
			"Entry" 
	};
	// @formatter:on

	private final static String ENTRY_NODE = "Entry";
	// "1";       // beginning of a block, someone calls it
	private final static String BODY_NODE = "Body";
	// "2";       // Body block, no flow
	private final static String EXIT_NODE = "Exit";
	// "3";       // Terminator
	private final static String SWITCH_NODE = "Switch";
	// "4";       // Switch/computed jump
	private final static String BAD_NODE = "Bad";
	// "5";       // Bad destination
	private final static String DATA_NODE = "Data";
	// "6";       // Data Node, used for indirection
	private final static String ENTRY_NEXUS = "Entry-Nexus";
	// "7";       //
	private final static String EXTERNAL_NODE = "External";
	// "8";       // node is external to program

	private final static String ENTRY_NEXUS_NAME = "Entry Points";
	private CodeBlockModel blockModel;
	private AddressSetView selection;
	private ProgramLocation location;
	private GraphDisplayProvider graphService;
	private boolean reuseGraph;
	private boolean appendGraph;
	private PluginTool tool;
	private String actionName;
	private Program program;


	public BlockGraphTask(String actionName, boolean graphEntryPointNexus, boolean showCode,
			boolean reuseGraph, boolean appendGraph, PluginTool tool, ProgramSelection selection,
			ProgramLocation location, CodeBlockModel blockModel,
			GraphDisplayProvider graphService) {

		super("Graph Program", true, false, true);
		this.actionName = actionName;

		this.graphEntryPointNexus = graphEntryPointNexus;
		this.showCode = showCode;
		this.reuseGraph = reuseGraph;
		this.appendGraph = appendGraph;
		this.tool = tool;
		this.blockModel = blockModel;
		this.graphService = graphService;
		this.colorizingService = tool.getService(ColorizingService.class);
		this.selection = selection;
		this.location = location;
		this.program = blockModel.getProgram();
	}

	/**
	 * Runs the move memory operation.
	 */
	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		AttributedGraph graph = createGraph();
		monitor.setMessage("Generating Graph...");
		try {
			GraphDisplay display = graphService.getGraphDisplay(reuseGraph, monitor);
			BlockModelGraphDisplayListener listener =
				new BlockModelGraphDisplayListener(tool, blockModel, display);
			display.setGraphDisplayListener(listener);

			if (showCode) {
				display.defineVertexAttribute(CODE_ATTRIBUTE);
				display.defineVertexAttribute(SYMBOLS_ATTRIBUTE);
				display.setVertexLabel(CODE_ATTRIBUTE, GraphDisplay.ALIGN_LEFT, 12, true,
					codeLimitPerBlock + 1);
			}
			display.setGraph(graph, actionName, appendGraph, monitor);

			if (location != null) {
				// initialize the graph location, but don't have the graph send an event
				String id = listener.getVertexIdForAddress(location.getAddress());
				display.setLocationFocus(id, EventTrigger.INTERNAL_ONLY);
			}
			if (selection != null && !selection.isEmpty()) {
				List<String> selectedVertices = listener.getVertices(selection);
				if (selectedVertices != null) {
					// intialize the graph selection, but don't have the graph send an event
					display.selectVertices(selectedVertices, EventTrigger.INTERNAL_ONLY);
				}
			}
		}
		catch (GraphException e) {
			if (!monitor.isCancelled()) {
				Msg.showError(this, null, "Graphing Error", e.getMessage());
			}
		}
	}

	/**
	 * Set the maximum number of code lines which will be used per block when
	 * showCode is enabled.
	 * @param maxLines maximum number of code lines
	 */
	public void setCodeLimitPerBlock(int maxLines) {
		codeLimitPerBlock = maxLines;
	}

	protected AttributedGraph createGraph() throws CancelledException {
		int blockCount = 0;
		AttributedGraph graph = new AttributedGraph();

		CodeBlockIterator it = getBlockIterator();
		List<AttributedVertex> entryPoints = new ArrayList<>();

		while (it.hasNext()) {
			CodeBlock curBB = it.next();
			Address start = graphBlock(graph, curBB, entryPoints);

			if (start != null && (++blockCount % 50) == 0) {
				taskMonitor.setMessage("Process Block: " + start.toString());
			}
		}

		// if option is set and there is more than one entry point vertex, create fake entry node
		// and connect to each entry point vertex
		if (graphEntryPointNexus && entryPoints.size() > 1) {
			addEntryEdges(graph, entryPoints);
		}

		return graph;
	}


	private CodeBlockIterator getBlockIterator() throws CancelledException {
		if (selection == null || selection.isEmpty()) {
			return blockModel.getCodeBlocks(taskMonitor);
		}
		return blockModel.getCodeBlocksContaining(selection, taskMonitor);
	}

	private Address graphBlock(AttributedGraph graph, CodeBlock curBB, List<AttributedVertex> entries)
			throws CancelledException {

		Address[] startAddrs = curBB.getStartAddresses();

		if (startAddrs == null || startAddrs.length == 0) {
			Msg.error(this, "Block not graphed, missing start address: " + curBB.getMinAddress());
			return null;
		}

		AttributedVertex vertex = graphBasicBlock(graph, curBB);

		if (graphEntryPointNexus && hasExternalEntryPoint(startAddrs)) {
			entries.add(vertex);
		}
		return startAddrs[0];
	}

	private boolean hasExternalEntryPoint(Address[] startAddrs) {
		SymbolTable symbolTable = program.getSymbolTable();
		for (Address address : startAddrs) {
			if (symbolTable.isExternalEntryPoint(address)) {
				return true;
			}
		}
		return false;
	}

	private void addEntryEdges(AttributedGraph graph, List<AttributedVertex> entries) {
		AttributedVertex entryNexusVertex = getEntryNexusVertex(graph);
		for (AttributedVertex vertex : entries) {
			AttributedEdge edge = graph.addEdge(entryNexusVertex, vertex);
			edge.setAttribute("Name", edgeNames[ENTRY]);
			edge.setAttribute("EdgeType", edgeTypes[ENTRY]);
		}
	}


	protected AttributedVertex graphBasicBlock(AttributedGraph graph, CodeBlock curBB)
			throws CancelledException {

		AttributedVertex fromVertex = getBasicBlockVertex(graph, curBB);

		// for each destination block
		//  create a vertex if it doesn't exit and add an edge to the destination vertex
		CodeBlockReferenceIterator refIter = curBB.getDestinations(taskMonitor);
		while (refIter.hasNext()) {
			CodeBlockReference cbRef = refIter.next();

			CodeBlock db = cbRef.getDestinationBlock();

			// must be a reference to a data block
			if (db == null) {
				continue;
			}

			// don't include destination if it does not overlap selection
			// always include if selection is empty
			if (selection != null && !selection.isEmpty() && !selection.intersects(db)) {
				continue;
			}

			AttributedVertex toVertex = getBasicBlockVertex(graph, db);
			if (toVertex == null) {
				continue;
			}

			//	put the edge in the graph
			String edgeAddr = cbRef.getReferent().toString();
			AttributedEdge newEdge = graph.addEdge(fromVertex, toVertex);

			// set it's attributes (really its name)
			setEdgeAttributes(newEdge, cbRef);
			setEdgeColor(newEdge, fromVertex, toVertex);

		}
		return fromVertex;
	}

	private void setEdgeColor(AttributedEdge edge, AttributedVertex fromVertex, AttributedVertex toVertex) {
		// color the edge: first on the 'from' vertex, then try to 'to' vertex
		String fromColor = fromVertex.getAttribute("Color");
		String toColor = toVertex.getAttribute("Color");
		if (fromColor != null || toColor != null) {
			if (fromColor != null) {
				edge.setAttribute("Color", fromColor);
			}
			else if (toColor != null) {
				edge.setAttribute("Color", toColor);
			}
		}
		
	}

	private String getVertexId(CodeBlock bb) {
		// vertex has attributes of Name       = Label
		//                          Address    = address of blocks start
		//                          VertexType = flow type of vertex
		Address addr = bb.getFirstStartAddress();
		if (addr.isExternalAddress()) {
			Symbol s = bb.getModel().getProgram().getSymbolTable().getPrimarySymbol(addr);
			return s.getName(true);
		}
		return addr.toString();
	}

	protected AttributedVertex getBasicBlockVertex(AttributedGraph graph, CodeBlock bb)
			throws CancelledException {

		String vertexId = getVertexId(bb);
		AttributedVertex vertex = graph.getVertex(vertexId);

		if (vertex != null) {
			return vertex;
		}

		String vertexName = bb.getName();
		vertex = graph.addVertex(vertexId, vertexName);

		// add attributes for this vertex -
		setVertexAttributes(vertex, bb, vertexName.equals(vertexId) ? false : isEntryNode(bb));

		if (showCode) {
			addSymbolAttribute(vertex, bb);
			addCodeAttribute(vertex, bb);
		}

		return vertex;
	}

	private void addCodeAttribute(AttributedVertex vertex, CodeBlock bb) {
		if (!bb.getMinAddress().isMemoryAddress()) {
			vertex.setAttribute(CODE_ATTRIBUTE, vertex.getAttribute(SYMBOLS_ATTRIBUTE));
		}

		Listing listing = program.getListing();
		CodeUnitIterator cuIter = listing.getCodeUnits(bb, true);
		int cnt = 0;
		int maxMnemonicFieldLen = 0;
		StringBuffer buf = new StringBuffer();
		while (cuIter.hasNext()) {
			CodeUnit cu = cuIter.next();
			if (cnt != 0) {
				buf.append('\n');
			}
			String line = cu.toString();
			int ix = line.indexOf(' ');
			if (ix > maxMnemonicFieldLen) {
				maxMnemonicFieldLen = ix;
			}
			buf.append(line);
			if (++cnt == codeLimitPerBlock) {
				buf.append("\n...");
				break;
			}
		}
		vertex.setAttribute(CODE_ATTRIBUTE, adjustCode(buf, maxMnemonicFieldLen + 1));
	}

	private void addSymbolAttribute(AttributedVertex vertex, CodeBlock bb) {
		Symbol[] symbols = program.getSymbolTable().getSymbols(bb.getMinAddress());
		if (symbols.length != 0) {
			StringBuffer buf = new StringBuffer();
			for (int i = 0; i < symbols.length; i++) {
				if (i != 0) {
					buf.append('\n');
				}
				buf.append(symbols[i].getName());
			}
			vertex.setAttribute(SYMBOLS_ATTRIBUTE, buf.toString());
		}

	}

	private String adjustCode(StringBuffer buf, int mnemonicFieldLen) {
		if (mnemonicFieldLen <= 1) {
			return buf.toString();
		}
		int ix = 0;
		char[] pad = new char[mnemonicFieldLen];
		Arrays.fill(pad, ' ');
		while (ix < buf.length()) {
			int eolIx = buf.indexOf("\n", ix);
			if (eolIx < 0) {
				eolIx = buf.length();
			}
			int padIx = buf.indexOf(" ", ix);
			if (padIx > 0 && padIx < eolIx) {
				int padSize = mnemonicFieldLen - padIx + ix;
				if (padSize > 0) {
					buf.insert(padIx, pad, 0, padSize);
					eolIx += padSize;
				}
			}
			ix = eolIx + 1;
		}
		return buf.toString();
	}

	/**
	 * Determine if the specified block is an entry node.
	 * @param block the basic block to test
	 * @return true  if the specified block is an entry node.
	 * @throws CancelledException if the operation is cancelled
	 */
	protected boolean isEntryNode(CodeBlock block) throws CancelledException {
		CodeBlockReferenceIterator iter = block.getSources(taskMonitor);
		boolean isSource = true;
		while (iter.hasNext()) {
			isSource = false;
			if (iter.next().getFlowType().isCall()) {
				return true;
			}
		}
		return isSource;
	}

	protected void setEdgeAttributes(AttributedEdge edge, CodeBlockReference ref) {

		int edgeType;
		FlowType flowType = ref.getFlowType();
		if (flowType == RefType.FALL_THROUGH) {
			edgeType = FALLTHROUGH;
		}
		else if (flowType == RefType.UNCONDITIONAL_JUMP) {
			edgeType = UNCONDITIONAL_JUMP;
		}
		else if (flowType == RefType.CONDITIONAL_JUMP) {
			edgeType = CONDITIONAL_JUMP;
		}
		else if (flowType == RefType.UNCONDITIONAL_CALL) {
			edgeType = UNCONDITIONAL_CALL;
		}
		else if (flowType == RefType.CONDITIONAL_CALL) {
			edgeType = CONDITIONAL_CALL;
		}
		else if (flowType.isComputed()) {
			edgeType = COMPUTED;
		}
		else if (flowType.isIndirect()) {
			edgeType = INDIRECTION;
		}
		else if (flowType == RefType.TERMINATOR) {
			edgeType = TERMINATOR;
		}
		else { // only FlowType.CONDITIONAL_TERMINATOR remains unchecked
			edgeType = CONDITIONAL_RETURN;
		}
		// set attributes on this edge
		edge.setAttribute("Name", edgeNames[edgeType]);
		edge.setAttribute("EdgeType", edgeTypes[edgeType]);
	}

	protected void setVertexAttributes(AttributedVertex vertex, CodeBlock bb, boolean isEntry) {

		String vertexType = BODY_NODE;

		Address firstStartAddress = bb.getFirstStartAddress();
		if (firstStartAddress.isExternalAddress()) {
			vertexType = EXTERNAL_NODE;
		}
		else if (isEntry) {
			vertexType = ENTRY_NODE;
		}
		else {
			FlowType flowType = bb.getFlowType();
			if (flowType.isTerminal()) {
				vertexType = EXIT_NODE;
			}
			else if (flowType.isComputed()) {
				vertexType = SWITCH_NODE;
			}
			else if (flowType == RefType.INDIRECTION) {
				vertexType = DATA_NODE;
			}
			else if (flowType == RefType.INVALID) {
				vertexType = BAD_NODE;
			}
		}

		vertex.setAttribute("VertexType", vertexType);

		setVertexColor(vertex, vertexType, firstStartAddress);
	}

	private void setVertexColor(AttributedVertex vertex, String vertexType, Address address) {

		if (colorizingService == null) {
			return;
		}

		Color color = colorizingService.getBackgroundColor(address);
		if (color == null) {
			return;
		}

		// color format: RGBrrrgggbbb
		// -where rrr/ggg/bbb is a three digit int value for each respective color range
		String rgb = "RGB" + HTMLUtilities.toRGBString(color);
		vertex.setAttribute("Color", rgb);  // sets the vertex color

		// This value triggers the vertex to be painted with its color and not a 
		// while background.
		if (showCode) {
			// our own custom override of Labels/Icons
			vertex.setAttribute("VertexType", "ColorFilled");
		}
		else {
			// the default preferences for VertexType
			vertex.setAttribute("VertexType", vertexType + ".Filled");
		}
	}

	private AttributedVertex getEntryNexusVertex(AttributedGraph graph) {
		AttributedVertex vertex = graph.getVertex(ENTRY_NEXUS_NAME);
		if (vertex == null) {
			vertex = graph.addVertex(ENTRY_NEXUS_NAME, ENTRY_NEXUS_NAME);
			vertex.setAttribute("VertexType", ENTRY_NEXUS);
		}
		return vertex;
	}
}
