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
package ghidra.app.plugin.core.function.tags;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.program.model.listing.FunctionTag;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class FunctionTagLoaderTest extends AbstractGhidraHeadedIntegrationTest {

	// @formatter:off

	// this xml is the same as what is loaded in Ghidra by default, 
	// located in Base/data/functionTags.xml
	private String FUNCTION_TAGS_DEFAULT = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
									+	"<tags>\n"
									+	"<tag> <name>COMPRESSION</name> <comment/> </tag>\n"
									+	"<tag> <name>CONSTRUCTOR</name> <comment/> </tag>\n"
									+	"<tag> <name>CRYPTO</name> <comment/> </tag>\n"
									+	"<tag> <name>DESTRUCTOR</name> <comment/> </tag>\n"
									+	"<tag> <name>IO</name> <comment/> </tag>\n"
									+	"<tag> <name>LIBRARY</name> <comment/> </tag>\n"
									+	"<tag> <name>NETWORK</name> <comment/> </tag>\n"
									+	"<tag> <name>UNPACKER</name> <comment/> </tag>\n"
									+	"</tags>\n";

	private String FUNCTION_TAGS_EMPTY_TAGS = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" 
											+ "<tags>\n" + "</tags>";

	private String FUNCTION_TAGS_HAS_BLANK_NAME_VALUE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			+	"<tags>\n"
			+	"<tag> <name>COMPRESSION</name> </tag>\n"
			+	"<tag> <name>CONSTRUCTOR</name> </tag>\n"
			+	"<tag> <name>CRYPTO</name> </tag>\n"
			// a name tag has a blank value
			+	"<tag> <name>  </name> " 
			+	"<comment>IM A COMMENT</comment> </tag>\n"

			+	"<tag> <name>IO</name> <comment/> </tag>\n"
			+	"<tag> <name>LIBRARY</name> <comment/> </tag>\n"
			+	"<tag> <name>NETWORK</name> <comment/> </tag>\n"
			+	"<tag> <name>UNPACKER</name> <comment/> </tag>\n"
			+	"</tags>\n";

	private String FUNCTION_TAGS_HAS_COMMENT_VALUE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
											+	"<tags>\n"
											+	"<tag> <name>COMPRESSION</name> </tag>\n"
											+	"<tag> <name>CONSTRUCTOR</name> </tag>\n"
											+	"<tag> <name>CRYPTO</name> </tag>\n"
											// a name tag has a comment value as well
											+	"<tag> <name>DESTRUCTOR</name> " 
											+	"<comment>IM A COMMENT</comment> </tag>\n"

											+	"<tag> <name>IO</name> <comment/> </tag>\n"
											+	"<tag> <name>LIBRARY</name> <comment/> </tag>\n"
											+	"<tag> <name>NETWORK</name> <comment/> </tag>\n"
											+	"<tag> <name>UNPACKER</name> <comment/> </tag>\n"
											+	"</tags>\n";
	
	private String FUNCTION_TAGS_HAS_NO_NAME_VALUE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			+	"<tags>\n"
			+	"<tag> <name>COMPRESSION</name> </tag>\n"
			+	"<tag> <name>CONSTRUCTOR</name> </tag>\n"
			+	"<tag> <name>CRYPTO</name> </tag>\n"
			// Create a comment tag with no name tag.
			+	"<tag> <comment>IM A COMMENT WITH NO NAME</comment> </tag>\n"
			+	"<tag> <name>IO</name> <comment/> </tag>\n"
			+	"<tag> <name>LIBRARY</name> <comment/> </tag>\n"
			+	"<tag> <name>NETWORK</name> <comment/> </tag>\n"
			+	"<tag> <name>UNPACKER</name> <comment/> </tag>\n"
			+	"</tags>\n";

	private String FUNCTION_TAGS_MALFORMED_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
											+	"<tags>\n"
											// end "tag" in start position
											+	"</tag> <name>COMPRESSION</name> </tag>\n" 
											+	"</tags>\n";

	private String FUNCTION_TAGS_NO_COMMENT_TAG = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
										+	"<tags>\n"
										+	"<tag> <name>COMPRESSION</name> </tag>\n"
										+	"<tag> <name>CONSTRUCTOR</name> </tag>\n"
										+	"<tag> <name>CRYPTO</name> </tag>\n"
										+	"<tag> <name>DESTRUCTOR</name> </tag>\n"
										+	"<tag> <name>IO</name> <comment/> </tag>\n"
										+	"<tag> <name>LIBRARY</name> </tag>\n"
										+	"<tag> <name>NETWORK</name> </tag>\n"
										+	"<tag> <name>UNPACKER</name> </tag>\n"
										+	"</tags>\n";


	// @formatter:on

	@Test
	public void testLoadTags_EmptyFile() throws Exception {
		// Create file without contents 
		File xxeFile = createTempFileForTest();
		List<FunctionTag> tags = FunctionTagLoader.loadTags(xxeFile);

		List<FunctionTag> expectedTags = new ArrayList<>();
		assertEquals(tags, expectedTags);
	}

	@Test
	public void testLoadTags_EmptyTags() throws Exception {
		// Create file with contents
		File xxeFile = createTempFileForTest();
		Files.write(xxeFile.toPath(), FUNCTION_TAGS_EMPTY_TAGS.getBytes());
		List<FunctionTag> tags = FunctionTagLoader.loadTags(xxeFile);

		List<FunctionTag> expectedTags = new ArrayList<>();
		assertEquals(tags, expectedTags);
	}

	@Test
	public void testLoadTags_FileDoesNotExist() throws Exception {
		// Create temp file, then delete it.
		File xxeFile = createTempFileForTest();
		xxeFile.delete();

		List<FunctionTag> tags = FunctionTagLoader.loadTags(xxeFile);

		List<FunctionTag> expectedTags = new ArrayList<>();
		assertEquals(tags, expectedTags);
	}

	@Test
	public void testLoadTags_MalformedXml() throws Exception {
		// Create file with contents
		File xxeFile = createTempFileForTest();
		Files.write(xxeFile.toPath(), FUNCTION_TAGS_MALFORMED_XML.getBytes());
		List<FunctionTag> tags = FunctionTagLoader.loadTags(xxeFile);

		List<FunctionTag> expectedTags = new ArrayList<>();
		assertEquals(tags, expectedTags);
	}

	@Test
	/**
	 * Test parsing xml that is the same as what is loaded in Ghidra by default, 
	 * located in Base/data/functionTags.xml
	 * @throws IOException
	 */
	public void testLoadTags_XmlDefault() throws IOException {

		// Create file with contents
		File xxeFile = createTempFileForTest();
		Files.write(xxeFile.toPath(), FUNCTION_TAGS_DEFAULT.getBytes());
		List<FunctionTag> tags = FunctionTagLoader.loadTags(xxeFile);

		List<FunctionTag> expectedTags = new ArrayList<>();
		expectedTags.add(new FunctionTagTemp("COMPRESSION", ""));
		expectedTags.add(new FunctionTagTemp("CONSTRUCTOR", ""));
		expectedTags.add(new FunctionTagTemp("CRYPTO", ""));
		expectedTags.add(new FunctionTagTemp("DESTRUCTOR", ""));
		expectedTags.add(new FunctionTagTemp("IO", ""));
		expectedTags.add(new FunctionTagTemp("LIBRARY", ""));
		expectedTags.add(new FunctionTagTemp("NETWORK", ""));
		expectedTags.add(new FunctionTagTemp("UNPACKER", ""));

		assertEquals(tags, expectedTags);
	}

	@Test
	public void testLoadTags_XmlHasBlankNameValue() throws IOException {

		// Create file with contents
		File xxeFile = createTempFileForTest();
		Files.write(xxeFile.toPath(), FUNCTION_TAGS_HAS_BLANK_NAME_VALUE.getBytes());
		List<FunctionTag> tags = FunctionTagLoader.loadTags(xxeFile);

		List<FunctionTag> expectedTags = new ArrayList<>();
		expectedTags.add(new FunctionTagTemp("COMPRESSION", ""));
		expectedTags.add(new FunctionTagTemp("CONSTRUCTOR", ""));
		expectedTags.add(new FunctionTagTemp("CRYPTO", ""));
		expectedTags.add(new FunctionTagTemp("IO", ""));
		expectedTags.add(new FunctionTagTemp("LIBRARY", ""));
		expectedTags.add(new FunctionTagTemp("NETWORK", ""));
		expectedTags.add(new FunctionTagTemp("UNPACKER", ""));

		assertEquals(tags, expectedTags);
	}

	@Test
	public void testLoadTags_XmlHasCommentValue() throws IOException {

		// Create file with contents
		File xxeFile = createTempFileForTest();
		Files.write(xxeFile.toPath(), FUNCTION_TAGS_HAS_COMMENT_VALUE.getBytes());
		List<FunctionTag> tags = FunctionTagLoader.loadTags(xxeFile);

		List<FunctionTag> expectedTags = new ArrayList<>();
		expectedTags.add(new FunctionTagTemp("COMPRESSION", ""));
		expectedTags.add(new FunctionTagTemp("CONSTRUCTOR", ""));
		expectedTags.add(new FunctionTagTemp("CRYPTO", ""));
		expectedTags.add(new FunctionTagTemp("DESTRUCTOR", "IM A COMMENT"));
		expectedTags.add(new FunctionTagTemp("IO", ""));
		expectedTags.add(new FunctionTagTemp("LIBRARY", ""));
		expectedTags.add(new FunctionTagTemp("NETWORK", ""));
		expectedTags.add(new FunctionTagTemp("UNPACKER", ""));

		assertEquals(tags, expectedTags);
	}

	@Test
	public void testLoadTags_XmlNoCommentTag() throws IOException {

		// Create file with contents
		File xxeFile = createTempFileForTest();
		Files.write(xxeFile.toPath(), FUNCTION_TAGS_NO_COMMENT_TAG.getBytes());
		List<FunctionTag> tags = FunctionTagLoader.loadTags(xxeFile);

		List<FunctionTag> expectedTags = new ArrayList<>();
		expectedTags.add(new FunctionTagTemp("COMPRESSION", ""));
		expectedTags.add(new FunctionTagTemp("CONSTRUCTOR", ""));
		expectedTags.add(new FunctionTagTemp("CRYPTO", ""));
		expectedTags.add(new FunctionTagTemp("DESTRUCTOR", ""));
		expectedTags.add(new FunctionTagTemp("IO", ""));
		expectedTags.add(new FunctionTagTemp("LIBRARY", ""));
		expectedTags.add(new FunctionTagTemp("NETWORK", ""));
		expectedTags.add(new FunctionTagTemp("UNPACKER", ""));

		assertEquals(tags, expectedTags);
	}

	@Test
	/**
	 * Test parsing xml with a comment tag but without a name tag. Skip creation of FunctionTag 
	 * (don't want one without a name).
	 *   
	 * @throws IOException
	 */
	public void testLoadTags_XmlNoNameTag() throws IOException {

		// Create file with contents
		File xxeFile = createTempFileForTest();
		Files.write(xxeFile.toPath(), FUNCTION_TAGS_HAS_NO_NAME_VALUE.getBytes());
		List<FunctionTag> tags = FunctionTagLoader.loadTags(xxeFile);

		List<FunctionTag> expectedTags = new ArrayList<>();
		expectedTags.add(new FunctionTagTemp("COMPRESSION", ""));
		expectedTags.add(new FunctionTagTemp("CONSTRUCTOR", ""));
		expectedTags.add(new FunctionTagTemp("CRYPTO", ""));
		expectedTags.add(new FunctionTagTemp("IO", ""));
		expectedTags.add(new FunctionTagTemp("LIBRARY", ""));
		expectedTags.add(new FunctionTagTemp("NETWORK", ""));
		expectedTags.add(new FunctionTagTemp("UNPACKER", ""));

		assertEquals(tags, expectedTags);
	}
}
