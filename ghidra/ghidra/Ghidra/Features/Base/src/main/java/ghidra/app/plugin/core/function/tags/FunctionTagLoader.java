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

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import org.xml.sax.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.listing.FunctionTag;
import ghidra.util.Msg;
import ghidra.xml.*;

/**
 * Reads function tags from  @see ghidra.framework.Application#getModuleDataFile(java.lang.String)
 * or a File on the filesytem.
 */
public class FunctionTagLoader {

	/**
	 * Load function tags from filesystem. Useful for unit tests.
	 * 
	 * @param tagFile tag file
	 * @return List list of function tags
	 */
	protected static List<FunctionTag> loadTags(File tagFile) {
		return loadTags(new ResourceFile(tagFile));
	}

	/**
	 * Load function tags from @see ghidra.framework.Application#getModuleDataFile(java.lang.String)
	 * 
	 * @param moduleDataFilePath data file loaded by Application
	 * @return List list of function tags
	 */
	protected static List<FunctionTag> loadTags(String moduleDataFilePath) {
		try {
			return loadTags(Application.getModuleDataFile(moduleDataFilePath));
		}
		catch (FileNotFoundException e) {
			Msg.error(null, "Error loading function tags file from " + moduleDataFilePath, e);
		}
		return new ArrayList<FunctionTag>();
	}

	protected static List<FunctionTag> loadTags(final ResourceFile tagDataFile) {
		List<FunctionTag> tags = new ArrayList<>();

		try {
			ErrorHandler errHandler = new ErrorHandler() {
				@Override
				public void error(SAXParseException exception) throws SAXException {
					throw new SAXException("Error: " + exception);
				}

				@Override
				public void fatalError(SAXParseException exception) throws SAXException {
					throw new SAXException("Fatal error: " + exception);
				}

				@Override
				public void warning(SAXParseException exception) throws SAXException {
					throw new SAXException("Warning: " + exception);
				}
			};

			XmlPullParser parser;
			try (InputStream inputStream = tagDataFile.getInputStream()) {
				parser = new NonThreadedXmlPullParserImpl(inputStream, tagDataFile.getName(),
					errHandler, false);
			}

			parser.start("tags");
			while (parser.hasNext()) {
				XmlElement el = parser.next();
				// Parse value of name tag.
				// Only the end XmlElement contains the inner text.
				if (el.isEnd() && "name".equals(el.getName())) {
					String name = el.getText();
					String comment = "";
					// If there's a name value, parse value of comment tag.
					// Add name, comment to list of tags.
					if (name != null && name.trim().length() != 0) {
						if (parser.hasNext() && "comment".equals(parser.peek().getName())) {
							el = parser.next();
							comment = parser.end().getText();
						}
						FunctionTagTemp tag = new FunctionTagTemp(name, comment);
						tags.add(tag);
					}
				}
			}
			parser.dispose();
		}
		catch (XmlException e) {
			Msg.error(null, "Error parsing function tags from " + tagDataFile, e);
		}
		catch (SAXException | IOException e) {
			Msg.error(null, "Error loading function tags from " + tagDataFile, e);
		}

		return tags;
	}
}
