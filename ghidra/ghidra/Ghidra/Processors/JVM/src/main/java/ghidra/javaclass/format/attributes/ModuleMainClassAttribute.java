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
package ghidra.javaclass.format.attributes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.javaclass.format.constantpool.ConstantPoolClassInfo;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Note: text based on/taken from jvms12.pdf
 * <p>
 * Objects of this class indicate the main class of a module.
 */
public class ModuleMainClassAttribute extends AbstractAttributeInfo {

	private short main_class_index;

	protected ModuleMainClassAttribute(BinaryReader reader) throws IOException {
		super(reader);
		main_class_index = reader.readNextShort();
	}

	/**
	 * {@code main_class index} must be a valid index into the constant pool. The entry at
	 * that index must be a {@link ConstantPoolClassInfo} structure representing the main
	 * class of the current module.
	 * @return index of main class.
	 */
	public int getMainClassIndex() {
		return main_class_index & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("ModuleMainClass_attribute");
		structure.add(WORD, "main_class_index", null);
		return structure;
	}

}
