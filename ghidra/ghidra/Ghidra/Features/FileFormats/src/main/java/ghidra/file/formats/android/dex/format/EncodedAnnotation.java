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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.*;

public class EncodedAnnotation implements StructConverter {

	private int typeIndex;
	private int typeIndexLength;// in bytes
	private int size;
	private int sizeLength;// in bytes
	private List< AnnotationElement > elements = new ArrayList< AnnotationElement >( );

	public EncodedAnnotation( BinaryReader reader ) throws IOException {
		typeIndex = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
		typeIndexLength = Leb128.unsignedLeb128Size( typeIndex );
		reader.readNextByteArray( typeIndexLength );// consume leb...

		size = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );
		sizeLength = Leb128.unsignedLeb128Size( size );
		reader.readNextByteArray( sizeLength );// consume leb...

		for ( int i = 0 ; i < size ; ++i ) {
			elements.add( new AnnotationElement( reader ) );
		}
	}

	public int getTypeIndex( ) {
		return typeIndex;
	}

	public int getSize( ) {
		return size;
	}

	public List<AnnotationElement> getElements() {
		return Collections.unmodifiableList( elements );
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		StringBuilder builder = new StringBuilder( );
		builder.append( "encoded_annotation" + "_" );
		builder.append( typeIndexLength + "_" );
		builder.append( sizeLength + "_" );
		builder.append( elements.size( ) + "_" );

		Structure structure = new StructureDataType( builder.toString( ), 0 );

		structure.add( new ArrayDataType( BYTE, typeIndexLength, BYTE.getLength( ) ), "typeIndex", null );
		structure.add( new ArrayDataType( BYTE, sizeLength, BYTE.getLength( ) ), "size", null );

		int index = 0;
		for ( AnnotationElement element : elements ) {
			DataType dataType = element.toDataType( );
			structure.add( dataType, "element" + index, null );
			++index;
			builder.append( "" + dataType.getName( ) );
		}

		structure.setCategoryPath( new CategoryPath( "/dex/encoded_annotation" ) );
		try {
			structure.setName( builder.toString( ) );
		}
		catch ( Exception e ) {
			// ignore
		}
		return structure;
	}

}
