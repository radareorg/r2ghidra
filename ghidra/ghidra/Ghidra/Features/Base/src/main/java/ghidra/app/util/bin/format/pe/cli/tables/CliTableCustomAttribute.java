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
package ghidra.app.util.bin.format.pe.cli.tables;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexCustomAttributeType;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexHasCustomAttribute;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.InvalidInputException;

/**
 * Describes the CustomAttribute table. 
 */
public class CliTableCustomAttribute extends CliAbstractTable {
	public class CliCustomAttributeRow extends CliAbstractTableRow {
		public int parentIndex;
		public int typeIndex;
		public int valueIndex;
		
		public CliCustomAttributeRow(int parentIndex, int typeIndex, int valueIndex) {
			super();
			this.parentIndex = parentIndex;
			this.typeIndex = typeIndex;
			this.valueIndex = valueIndex;
		}

		@Override
		public String getRepresentation() {
			String parentRep, typeRep;
			try {
				parentRep = getRowRepresentationSafe(CliIndexHasCustomAttribute.getTableName(parentIndex), CliIndexHasCustomAttribute.getRowIndex(parentIndex));
			}
			catch (InvalidInputException e) {
				parentRep = Integer.toHexString(parentIndex);
			}
			try {
				typeRep = getRowRepresentationSafe(CliIndexCustomAttributeType.getTableName(parentIndex), CliIndexCustomAttributeType.getRowIndex(parentIndex));
			}
			catch (InvalidInputException e) {
				typeRep = Integer.toHexString(typeIndex);
			}
			return String.format("Parent %s Type %s Value %x", parentRep, typeRep, valueIndex);
		}
	}
	public CliTableCustomAttribute(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliCustomAttributeRow row = new CliCustomAttributeRow(CliIndexHasCustomAttribute.readCodedIndex(reader, stream), 
				CliIndexCustomAttributeType.readCodedIndex(reader, stream), readBlobIndex(reader));
			rows.add(row);
			blobs.add(row.valueIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "CustomAttribute Row", 0);
		rowDt.add(CliIndexHasCustomAttribute.toDataType(metadataStream), "Parent", null);
		rowDt.add(CliIndexCustomAttributeType.toDataType(metadataStream), "Type", null);
		rowDt.add(metadataStream.getBlobIndexDataType(), "Value", null);
		return rowDt;
	}
}
