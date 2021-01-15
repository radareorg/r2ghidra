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
import java.util.ArrayList;
import java.util.List;

public class EncodedCatchHandlerList implements StructConverter {

	private int size;
	private int sizeLength;// in bytes
	private List< EncodedCatchHandler > handlers = new ArrayList< EncodedCatchHandler >( );

	public EncodedCatchHandlerList( BinaryReader reader ) throws IOException {
		size = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
		sizeLength = Leb128.unsignedLeb128Size( size );
		reader.readNextByteArray( sizeLength );// consume leb...

		for ( int i = 0 ; i < size ; ++i ) {
			handlers.add( new EncodedCatchHandler( reader ) );
		}
	}

	/**
	 * size of this list, in entries
	 */
	public int getSize( ) {
		return size;
	}

	public List< EncodedCatchHandler > getHandlers( ) {
		return handlers;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
//		int unique = 0;
		String name = "encoded_catch_handler_list" + "_" + sizeLength;
		Structure structure = new StructureDataType( name, 0 );
		structure.add( new ArrayDataType( BYTE, sizeLength, BYTE.getLength( ) ), "size", null );
//		int index = 0;
//		for ( EncodedCatchHandler handler : handlers ) {
//			DataType dataType = handler.toDataType( );
//			structure.add( dataType, "handler_" + index, null );
//			unique += dataType.getLength( );
//		}
		structure.setCategoryPath( new CategoryPath( "/dex/encoded_catch_handler_list" ) );
//		try {
//			structure.setName( name + "_" + Integer.toHexString( unique ) );
//		}
//		catch ( Exception e ) {
//			// ignore
//		}
		return structure;
	}

}
