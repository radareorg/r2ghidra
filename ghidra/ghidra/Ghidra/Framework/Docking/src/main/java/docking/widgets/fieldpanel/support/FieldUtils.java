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
package docking.widgets.fieldpanel.support;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.field.FieldElement;

/**
 * A utility class for working with Field objects.
 */
public class FieldUtils {

	private static final char[] WHITE_SPACE = new char[] { '\t', '\n', '\r', '\f' };

	private FieldUtils() { // utility class
	}

	public static List<FieldElement> wrap(List<FieldElement> fieldElements, int width) {
		List<FieldElement> wrappedElements = new ArrayList<FieldElement>();
		for (FieldElement fieldElement : fieldElements) {
			wrappedElements.addAll(wordWrapList(fieldElement, width));
		}
		return wrappedElements;
	}

	/**
	 * Splits the given FieldElement into sub-elements by wrapping the element on whitespace.
	 * 
	 * @param fieldElement The element to wrap
	 * @param width The maximum width to allow before wrapping 
	 * @return The wrapped elements
	 */
	public static FieldElement[] wrap(FieldElement fieldElement, int width) {

		FieldElement originalFieldElement = fieldElement.replaceAll(WHITE_SPACE, ' ');
		if (originalFieldElement.getStringWidth() <= width) {
			return new FieldElement[] { originalFieldElement };
		}

		List<FieldElement> lines = new ArrayList<FieldElement>();
		int wordWrapPos = findWordWrapPosition(originalFieldElement, width);
		while (wordWrapPos > 0) {
			lines.add(originalFieldElement.substring(0, wordWrapPos));
			if (originalFieldElement.charAt(wordWrapPos) == ' ') {
				wordWrapPos++; 	// skip white space char
			}
			originalFieldElement = originalFieldElement.substring(wordWrapPos);
			wordWrapPos = findWordWrapPosition(originalFieldElement, width);
		}
		lines.add(originalFieldElement);
		return lines.toArray(new FieldElement[lines.size()]);
	}

	/**
	 * Splits the given FieldElement into sub-elements by wrapping the element on whitespace.
	 * 
	 * @param fieldElement The element to wrap
	 * @param width The maximum width to allow before wrapping 
	 * @return The wrapped elements
	 */
	public static List<FieldElement> wordWrapList(FieldElement fieldElement, int width) {
		List<FieldElement> lines = new ArrayList<FieldElement>();

		FieldElement originalFieldElement = fieldElement.replaceAll(WHITE_SPACE, ' ');
		if (originalFieldElement.getStringWidth() <= width) {
			lines.add(originalFieldElement);
			return lines;
		}

		int wordWrapPos = findWordWrapPosition(originalFieldElement, width);
		while (wordWrapPos > 0) {
			lines.add(originalFieldElement.substring(0, wordWrapPos));
			if (originalFieldElement.charAt(wordWrapPos) == ' ') {
				wordWrapPos++; 	// skip white space char
			}
			originalFieldElement = originalFieldElement.substring(wordWrapPos);
			wordWrapPos = findWordWrapPosition(originalFieldElement, width);
		}
		lines.add(originalFieldElement);
		return lines;
	}

	/**
	 * Finds the position within the given element at which to split the line for word wrapping.
	 * This method only breaks on whitespace characters. It finds the last whitespace character
	 * that completely fits within the given width.  If there is no whitespace character before
	 * the width break point, it finds the first whitespace character after the width.  If the
	 * element cannot be split at all, it returns 0.
	 * @param element the element to split
	 * @param width the max width to allow before looking for a word wrap positions
	 * @return 0 if the element cannot be split, else the character position of the string
	 * to be split off.
	 */
	private static int findWordWrapPosition(FieldElement element, int width) {

		String text = element.getText();
		int wrapPosition = element.getMaxCharactersForWidth(width);
		if (wrapPosition == element.length() || wrapPosition == 0) {
			return 0;
		}

		int whiteSpacePosition = text.lastIndexOf(" ", wrapPosition - 1);
		if (whiteSpacePosition >= 0) {
			return whiteSpacePosition;
		}

		return wrapPosition;
		// The following code was replace with the return just above.  This has the effect
		// of splitting contiguous words at the field width instead of at the next white 
		// space beyond.
//		whiteSpacePosition = text.indexOf(" ", wrapPosition);
//		if (whiteSpacePosition >= 0) {
//			if (whiteSpacePosition + 1 >= element.length()) {  // if whitespace at end, no split
//				return 0;
//			}
//			return whiteSpacePosition;
//		}
//		return 0;
	}

	/**
	 * Trims "goofy" characters off of the given label, like spaces, '[',']', etc.
	 * @param string The string to be trimmed
	 * @return The trimmed string.
	 */
	public static String trimString(String string) {
		// short-circuit case where the given string starts normally, but contains invalid
		// characters (e.g., param_1[EAX])
		StringBuffer buffer = new StringBuffer(string);
		if (Character.isJavaIdentifierPart(buffer.charAt(0))) {
			// in this case just take all valid characters and then exit            
			for (int index = 1; index < buffer.length(); index++) {
				int charAt = buffer.charAt(index);
				if (!Character.isJavaIdentifierPart(charAt)) {
					return buffer.substring(0, index);
				}
			}
			return buffer.toString();
		}

		// the following case is when the given string is surrounded by "goofy" characters        
		int index = 0;
		int charAt = buffer.charAt(index);
		while (!Character.isJavaIdentifierPart(charAt) && buffer.length() > 0) {
			buffer.deleteCharAt(0);
			charAt = buffer.charAt(0);
		}

		index = buffer.length() - 1;
		charAt = buffer.charAt(index);
		while (!Character.isJavaIdentifierPart(charAt) && index > 0) {
			buffer.deleteCharAt(index);
			charAt = buffer.charAt(--index);
		}

		return buffer.toString();
	}

}
