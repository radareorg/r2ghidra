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
package ghidra.graph.export;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.junit.*;

import ghidra.app.plugin.core.blockmodel.BlockModelServicePlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.graph.GraphDisplayBrokerPlugin;
import ghidra.app.services.BlockModelService;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.database.ProgramDB;
import ghidra.service.graph.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class GraphExportTest extends AbstractGhidraHeadedIntegrationTest {
	protected PluginTool tool;
	protected ProgramDB program;
	protected TestEnv env;
	protected BlockModelService blockModelService;
	protected CodeBrowserPlugin codeBrowser;
	private GraphExporterDialog dialog;

	@Before
	public void setUp() throws Exception {

		setErrorGUIEnabled(false);

		env = new TestEnv();
		tool = env.getTool();

		initializeTool();
		GraphDisplayBroker broker = tool.getService(GraphDisplayBroker.class);
		GraphDisplayProvider exportProvider = broker.getGraphDisplayProvider("Graph Export");

		AttributedGraph graph = createGraph();
		GraphDisplay exporter = exportProvider.getGraphDisplay(false, TaskMonitor.DUMMY);
		exporter.setGraph(graph, "Test", false, TaskMonitor.DUMMY);
		waitForSwing();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testCSV() throws Exception {
		List<String> lines = processDialog(GraphExportFormat.CSV);

		assertOutput(lines,
			"A,B",
			"B,C",
			"B,D",
			"C,E",
			"D,E");
	}

	@Test
	public void testDIMACS() throws Exception {
		List<String> lines = processDialog(GraphExportFormat.DIMACS);
		assertOutput(lines,
			"c",
			"c SOURCE: Generated using the JGraphT library",
			"c",
			"p edge 5 5",
			"e A B",
			"e B C",
			"e B D",
			"e C E",
			"e D E");
	}

	@Test
	public void testDOT() throws Exception {
		List<String> lines = processDialog(GraphExportFormat.DOT);

		assertOutput(lines,
			"digraph Ghidra {",
			"  A [ Type=\"X\" Inverted=\"true\" Name=\"A\" ];",
			"  B [ Type=\"Y\" Name=\"B\" ];",
			"  C [ Type=\"Y\" Name=\"C\" ];",
			"  D [ Type=\"Y\" Name=\"D\" ];",
			"  E [ Type=\"Z\" Name=\"E\" ];",
			"  A -> B [ EType=\"Fall\" ];",
			"  B -> C [ EType=\"JMP\" ];",
			"  B -> D [ EType=\"Fall\" ];",
			"  C -> E [ EType=\"Fall\" ];",
			"  D -> E [ EType=\"Call\" ];",
			"}");
	}

	@Test
	public void testGML() throws Exception {
		List<String> lines = processDialog(GraphExportFormat.GML);
		assertOutput(lines,
			"Creator \"JGraphT GML Exporter\"",
			"Version 1",
			"graph",
			"[",
			"	label \"\"",
			"	directed 1",
			"	node",
			"	[",
			"		id A",
			"	]",
			"	node",
			"	[",
			"		id B",
			"	]",
			"	node",
			"	[",
			"		id C",
			"	]",
			"	node",
			"	[",
			"		id D",
			"	]",
			"	node",
			"	[",
			"		id E",
			"	]",
			"	edge",
			"	[",
			"		id 1",
			"		source A",
			"		target B",
			"	]",
			"	edge",
			"	[",
			"		id 2",
			"		source B",
			"		target C",
			"	]",
			"	edge",
			"	[",
			"		id 3",
			"		source B",
			"		target D",
			"	]",
			"	edge",
			"	[",
			"		id 4",
			"		source C",
			"		target E",
			"	]",
			"	edge",
			"	[",
			"		id 5",
			"		source D",
			"		target E",
			"	]",
			"]");
	}

	@Test
	public void testGRAPHML() throws Exception {
		List<String> lines = processDialog(GraphExportFormat.GRAPHML);
		assertOutput(lines,
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?><graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\" xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">",
			"    <graph edgedefault=\"directed\">",
			"        <node id=\"A\"/>",
			"        <node id=\"B\"/>",
			"        <node id=\"C\"/>",
			"        <node id=\"D\"/>",
			"        <node id=\"E\"/>",
			"        <edge id=\"1\" source=\"A\" target=\"B\"/>",
			"        <edge id=\"2\" source=\"B\" target=\"C\"/>",
			"        <edge id=\"3\" source=\"B\" target=\"D\"/>",
			"        <edge id=\"4\" source=\"C\" target=\"E\"/>",
			"        <edge id=\"5\" source=\"D\" target=\"E\"/>",
			"    </graph>",
			"</graphml>");

	}

	@Test
	public void testJSON() throws Exception {
		List<String> lines = processDialog(GraphExportFormat.JSON);
		assertOutput(lines,
			"{\"creator\":\"JGraphT JSON Exporter\",\"version\":\"1\",\"nodes\":" +
				"[{\"id\":\"A\",\"Type\":\"X\",\"Inverted\":\"true\",\"Name\":\"A\"}," +
				"{\"id\":\"B\",\"Type\":\"Y\",\"Name\":\"B\"}," +
				"{\"id\":\"C\",\"Type\":\"Y\",\"Name\":\"C\"}," +
				"{\"id\":\"D\",\"Type\":\"Y\",\"Name\":\"D\"}," +
				"{\"id\":\"E\",\"Type\":\"Z\",\"Name\":\"E\"}]," +
				"\"edges\":[{\"id\":\"1\",\"source\":\"A\",\"target\":\"B\",\"EType\":\"Fall\"}," +
				"{\"id\":\"2\",\"source\":\"B\",\"target\":\"C\",\"EType\":\"JMP\"}," +
				"{\"id\":\"3\",\"source\":\"B\",\"target\":\"D\",\"EType\":\"Fall\"}," +
				"{\"id\":\"4\",\"source\":\"C\",\"target\":\"E\",\"EType\":\"Fall\"}," +
				"{\"id\":\"5\",\"source\":\"D\",\"target\":\"E\",\"EType\":\"Call\"}]}");

	}

	@Test
	public void testLEMON() throws Exception {
		List<String> lines = processDialog(GraphExportFormat.LEMON);

		assertOutput(lines,
			"#Creator: JGraphT Lemon (LGF) Exporter",
			"#Version: 1",
			"",
			"@nodes",
			"label",
			"A",
			"B",
			"C",
			"D",
			"E",
			"",
			"@arcs",
			"		-",
			"A	B",
			"B	C",
			"B	D",
			"C	E",
			"D	E",
			"");
	}

	@Test
	public void testMATRIX() throws Exception {
		List<String> lines = processDialog(GraphExportFormat.MATRIX);
		assertOutput(lines,
			"A B 1",
			"B C 1",
			"B D 1",
			"C E 1",
			"D E 1");
	}

	@Test
	public void testVISIO() throws Exception {
		List<String> lines = processDialog(GraphExportFormat.VISIO);
		assertOutput(lines,
			"Shape,A,,A",
			"Shape,B,,B",
			"Shape,C,,C",
			"Shape,D,,D",
			"Shape,E,,E",
			"Link,A-->B,,,A,B",
			"Link,B-->C,,,B,C",
			"Link,B-->D,,,B,D",
			"Link,C-->E,,,C,E",
			"Link,D-->E,,,D,E");
	}

	protected void initializeTool() throws Exception {
		installPlugins();

		showTool(tool);
	}

	protected void installPlugins() throws PluginException {
		tool.addPlugin(BlockModelServicePlugin.class.getName());
		tool.addPlugin(GraphDisplayBrokerPlugin.class.getName());
	}

	private List<String> processDialog(GraphExportFormat format) throws IOException {
		dialog = getDialogComponent(GraphExporterDialog.class);
		String filePath =
			createTempFilePath("GraphExportTest", "." + format.getDefaultFileExtension());
		runSwing(() -> dialog.setOutputFile(filePath));
		dialog.setExportFormat(format);
		pressButtonByText(dialog, "OK");
		List<String> lines = FileUtilities.getLines(new File(filePath));
		return lines;

	}

	private AttributedGraph createGraph() {
		AttributedGraph graph = new AttributedGraph();
		AttributedVertex vA = graph.addVertex("A");
		AttributedVertex vB = graph.addVertex("B");
		AttributedVertex vC = graph.addVertex("C");
		AttributedVertex vD = graph.addVertex("D");
		AttributedVertex vE = graph.addVertex("E");

		//		A
		//		|
		//	    B
		//     / \
		//    C   D
		//    \  /
		//      E

		AttributedEdge e1 = graph.addEdge(vA, vB);
		AttributedEdge e2 = graph.addEdge(vB, vC);
		AttributedEdge e3 = graph.addEdge(vB, vD);
		AttributedEdge e4 = graph.addEdge(vC, vE);
		AttributedEdge e5 = graph.addEdge(vD, vE);

		vA.setAttribute("Type", "X");
		vB.setAttribute("Type", "Y");
		vC.setAttribute("Type", "Y");
		vD.setAttribute("Type", "Y");
		vE.setAttribute("Type", "Z");

		e1.setAttribute("EType", "Fall");
		e2.setAttribute("EType", "JMP");
		e3.setAttribute("EType", "Fall");
		e4.setAttribute("EType", "Fall");
		e5.setAttribute("EType", "Call");

		vA.setAttribute("Inverted", "true");
		return graph;
	}

	private void printLines(List<String> lines) {
		Msg.debug(this, "\n" + testName.getMethodName());
		for (String line : lines) {
			Msg.debug(this, "\"" + line + "\",");
		}
	}

	private void assertOutput(List<String> actual, String... expected) {
		try {
			for (int i = 0; i < expected.length; i++) {
				if (i >= actual.size()) {
					fail(testName.getMethodName() + ": output line " + (i + 1) + ": expected :\"" +
						expected[i] +
						"\", got: EOF");
				}
				assertEquals(testName.getMethodName() + ": output line " + (i + 1) + ": ",
					expected[i],
					actual.get(i));
			}
		}
		catch (Throwable e) {
			printLines(actual);
			throw e;
		}
	}

}
