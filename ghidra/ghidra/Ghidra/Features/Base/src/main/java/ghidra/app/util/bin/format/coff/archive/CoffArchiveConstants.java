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
package ghidra.app.util.bin.format.coff.archive;

public final class CoffArchiveConstants {

	public final static String MAGIC      = "!<arch>\n";
	public final static int    MAGIC_LEN  = MAGIC.length();
	public static final int MAGIC_LEN_CONST_EXPR = 8;
	public static final byte[] MAGIC_BYTES = MAGIC.getBytes();

	public final static String END_OF_HEADER_MAGIC = "'\n";
}
