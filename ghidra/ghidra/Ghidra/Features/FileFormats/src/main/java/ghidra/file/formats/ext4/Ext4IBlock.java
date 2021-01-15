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
package ghidra.file.formats.ext4;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.*;

public class Ext4IBlock implements StructConverter {
	
	private Ext4ExtentHeader header;
	private List<Ext4ExtentIdx> indexEntries;
	private List<Ext4Extent> extentEntries;
	private byte[] extra;
	
	private boolean isExtentTree;
	
	public Ext4IBlock(ByteProvider provider, boolean isExtentTree) throws IOException {
		this( new BinaryReader( provider, true ), isExtentTree );
	}
	
	public Ext4IBlock(BinaryReader reader, boolean isExtentTree) throws IOException {
		this.isExtentTree = isExtentTree;
		int count = 0;
		if( isExtentTree ) {
			header = new Ext4ExtentHeader(reader);
			count++;
			short numEntries = header.getEh_entries();
			if( header.getEh_depth() > 0 ) {
				indexEntries = new ArrayList<Ext4ExtentIdx>();
				for( int i = 0; i < numEntries; i++ ) {
					indexEntries.add( new Ext4ExtentIdx(reader) );
					count++;
				}
			}
			else {
				extentEntries = new ArrayList<Ext4Extent>();
				for( int i = 0; i < numEntries; i++ ) {
					extentEntries.add( new Ext4Extent(reader) );
					count++;
				}
			}
		}
		
		int extraBytes = 60 - (count * 12);
		if ( extraBytes > 0 ) {
			extra = reader.readNextByteArray(extraBytes);
		}
		else {
			extra = new byte[ 0 ];
		}
	}

	public Ext4ExtentHeader getHeader() {
		return header;
	}

	public List<Ext4ExtentIdx> getIndexEntries() {
		if ( indexEntries == null ) {
			return Collections.emptyList( );
		}
		return indexEntries;
	}

	public List<Ext4Extent> getExtentEntries() {
		if ( extentEntries == null ) {
			return Collections.emptyList( );
		}
		return extentEntries;
	}

	public byte[] getExtra() {
		return extra;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure;
		if( isExtentTree ) {
			structure = new StructureDataType("ext4_i_block_" + header.getEh_depth() + "_" + header.getEh_entries(), 0);
			structure.add( header.toDataType(), "header", null );
			if( extentEntries != null ) {
				for (int i = 0; i < extentEntries.size(); i++ ) {
					structure.add(extentEntries.get(i).toDataType(), "entry_" + i, null);
				}
			}
			if( indexEntries != null ) {
				for (int i = 0; i < indexEntries.size(); i++ ) {
					structure.add(indexEntries.get(i).toDataType(), "idx_" + i, null);
				}
			}
		} else {
			structure = new StructureDataType("ext4_i_block", 0);
		}
		// empty structures still have a length of 1, but byte array should be 60 bytes, not 59
		int extra = structure.getLength() == 1 ? 60 : 60 - structure.getLength();
		if( extra > 0 ) {
			structure.add( new ArrayDataType(BYTE, extra, BYTE.getLength()), "extra", null);
		}
		return structure;
	}

}
