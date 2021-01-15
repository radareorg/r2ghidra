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
package ghidra.program.model.data;

/**
 * Basic implementation for an unsigned Integer dataType 
 */
public class UnsignedIntegerDataType extends AbstractIntegerDataType {

	private final static long serialVersionUID = 1;

	/** A statically defined UnsignedIntegerDataType instance.*/
	public final static UnsignedIntegerDataType dataType = new UnsignedIntegerDataType();

	public UnsignedIntegerDataType() {
		this(null);
	}

	public UnsignedIntegerDataType(DataTypeManager dtm) {
		super("uint", false, dtm);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	@Override
	public int getLength() {
		return getDataOrganization().getIntegerSize();
	}

	/**
	 * @see ghidra.program.model.data.DataType#isDynamicallySized()
	 */
	@Override
	public boolean isDynamicallySized() {
		return true;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	@Override
	public String getDescription() {
		return "Unsigned Integer (compiler-specific size)";
	}

	@Override
	public String getCDeclaration() {
		return C_UNSIGNED_INT;
	}

	@Override
	public IntegerDataType getOppositeSignednessDataType() {
		return IntegerDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public UnsignedIntegerDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UnsignedIntegerDataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(getName(), "unsigned int", false); // standard C-primitive type with modified name
	}

}
