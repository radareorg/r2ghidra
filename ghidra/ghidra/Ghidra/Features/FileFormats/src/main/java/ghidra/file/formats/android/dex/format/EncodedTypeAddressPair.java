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
package ghidra.file.formats.android.dex.format;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.android.dex.util.Leb128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class EncodedTypeAddressPair implements StructConverter {

	private int typeIndex;
	private int address;

	private int typeIndexLength;// in bytes
	private int addressLength;// in bytes

	public EncodedTypeAddressPair( BinaryReader reader ) throws IOException {
		typeIndex = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
		typeIndexLength = Leb128.unsignedLeb128Size( typeIndex );
		reader.readNextByteArray( typeIndexLength );// consume leb...

		address = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
		addressLength = Leb128.unsignedLeb128Size( address );
		reader.readNextByteArray( addressLength );// consume leb...
	}

	public int getTypeIndex( ) {
		return typeIndex;
	}

	public int getAddress( ) {
		return address;
	}

	/**
	 * This method is only used for data type creation.
	 * Makes names unique to prevent ".conflicts".
	 */
	String getDataTypeIdString() {
		return typeIndexLength + "" + addressLength;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "encoded_type_addr_pair_" + typeIndexLength + "_" + addressLength, 0 );
		structure.add( new ArrayDataType( BYTE, typeIndexLength, BYTE.getLength( ) ), "type_idx", null );
		structure.add( new ArrayDataType( BYTE, addressLength, BYTE.getLength( ) ), "addr", null );
		structure.setCategoryPath( new CategoryPath( "/dex/encoded_type_addr_pair" ) );
		return structure;
	}
}
