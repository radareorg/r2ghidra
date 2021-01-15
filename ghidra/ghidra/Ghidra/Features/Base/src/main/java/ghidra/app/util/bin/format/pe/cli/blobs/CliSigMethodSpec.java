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
package ghidra.app.util.bin.format.pe.cli.blobs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.program.model.data.*;
import ghidra.util.exception.InvalidInputException;

public class CliSigMethodSpec extends CliAbstractSig {

	public static final byte identifier = 0x0a;
	
	private byte firstByte;
	private int genArgCount;
	private int genArgCountBytes;
	private CliSigType types[];
	
	public CliSigMethodSpec(CliBlob blob) throws IOException {
		super(blob);

		BinaryReader reader = getContentsReader();
		firstByte = reader.readNextByte();
		if (firstByte != identifier)
			return; // TODO: Do something worse?
		long origIndex = reader.getPointerIndex();
		genArgCount = decodeCompressedUnsignedInt(reader);
		genArgCountBytes = (int) (reader.getPointerIndex() - origIndex);
		types = new CliSigType[genArgCount];
		for (int i = 0; i < genArgCount; i++) {
			try {
				types[i] = readCliType(reader);
			}
			catch (InvalidInputException e) {
				types[i] = null;
			}
		}
	}

	@Override
	public String getContentsName() {
		return "MethodSpecSig";
	}
	
	@Override
	public String getContentsComment() {
		return "Specifies a generic method with GenArgCount types";
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(BYTE, "GenericInstByte", "GenericInst");
		struct.add(getDataTypeForBytes(genArgCountBytes), "GenArgCount", "Number types to follow");
		for (int i = 0; i < types.length; i++) {
			struct.add(types[i].getDefinitionDataType(), "Type"+i, null);
		}
		return struct;
	}

	@Override
	public String getRepresentationCommon(CliStreamMetadata stream, boolean isShort) {
		String typesRep = "";
		for (CliSigType type : types) {
			if (type == null) 
				typesRep += "unidentified_param_type, ";
			else
				typesRep += getRepresentationOf(type, stream, isShort) + ", ";
		}
		if (types.length > 0)
			typesRep = typesRep.substring(0, typesRep.length()-2); // Take off last comma+space
		String rep = String.format("GenericInst %d %s", genArgCount, typesRep);
		return rep;
	}
	
}
