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
package ghidra.app.util.bin.format.elf;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteArrayConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.util.DataConverter;
import ghidra.util.Msg;

/**
 * A container class to hold ELF relocations.
 */
public class ElfRelocationTable implements ElfFileSection, ByteArrayConverter {

	public enum TableFormat {
		DEFAULT, ANDROID;
	}

	private TableFormat format;

	private ElfSectionHeader sectionToBeRelocated;

	private ElfSymbolTable symbolTable;

	private ElfSectionHeader relocTableSection; // may be null
	private long fileOffset;
	private long addrOffset;
	private long length;
	private long entrySize;

	private boolean addendTypeReloc;
	private GenericFactory factory;
	private ElfHeader elfHeader;

	private ElfRelocation[] relocs;

	/**
	 * Create an Elf Relocation Table
	 * @param reader
	 * @param header elf header
	 * @param relocTableSection relocation table section header or null if associated with a dynamic table entry
	 * @param fileOffset relocation table file offset
	 * @param addrOffset memory address of relocation table (should already be adjusted for prelink)
	 * @param length length of relocation table in bytes
	 * @param entrySize size of each relocation entry in bytes
	 * @param addendTypeReloc true if addend type relocation table
	 * @param symbolTable associated symbol table
	 * @param sectionToBeRelocated or null for dynamic relocation table
	 * @param format table format
	 * @return Elf relocation table object
	 * @throws IOException
	 */
	static ElfRelocationTable createElfRelocationTable(FactoryBundledWithBinaryReader reader,
			ElfHeader header, ElfSectionHeader relocTableSection, long fileOffset, long addrOffset,
			long length, long entrySize, boolean addendTypeReloc, ElfSymbolTable symbolTable,
			ElfSectionHeader sectionToBeRelocated, TableFormat format) throws IOException {
		ElfRelocationTable elfRelocationTable =
			(ElfRelocationTable) reader.getFactory().create(ElfRelocationTable.class);
		elfRelocationTable.initElfRelocationTable(reader, header, relocTableSection, fileOffset,
			addrOffset, length, entrySize, addendTypeReloc, symbolTable, sectionToBeRelocated,
			format);
		return elfRelocationTable;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ElfRelocationTable() {
	}

	private void initElfRelocationTable(FactoryBundledWithBinaryReader reader, ElfHeader header,
			ElfSectionHeader relocTableSection, long fileOffset, long addrOffset, long length,
			long entrySize, boolean addendTypeReloc, ElfSymbolTable symbolTable,
			ElfSectionHeader sectionToBeRelocated, TableFormat format) throws IOException {

		this.relocTableSection = relocTableSection;
		this.fileOffset = fileOffset;
		this.addrOffset = addrOffset;
		this.length = length;
		this.entrySize = entrySize;
		this.addendTypeReloc = addendTypeReloc;
		this.elfHeader = header;
		this.factory = reader.getFactory();
		this.format = format;

		this.sectionToBeRelocated = sectionToBeRelocated;
		this.symbolTable = symbolTable;

		long ptr = reader.getPointerIndex();
		reader.setPointerIndex(fileOffset);

		List<ElfRelocation> relocList;
		if (format == TableFormat.ANDROID) {
			relocList = parseAndroidRelocations(reader);
		}
		else {
			relocList = parseStandardRelocations(reader);
		}

		reader.setPointerIndex(ptr);

		relocs = new ElfRelocation[relocList.size()];
		relocList.toArray(relocs);
	}

	private List<ElfRelocation> parseStandardRelocations(FactoryBundledWithBinaryReader reader)
			throws IOException {

		List<ElfRelocation> relocations = new ArrayList<>();
		int nRelocs = (int) (length / entrySize);
		for (int relocationIndex = 0; relocationIndex < nRelocs; ++relocationIndex) {
			relocations.add(ElfRelocation.createElfRelocation(reader, elfHeader, relocationIndex,
				addendTypeReloc));
		}
		return relocations;
	}

	private List<ElfRelocation> parseAndroidRelocations(FactoryBundledWithBinaryReader reader)
			throws IOException {

		String identifier = reader.readNextAsciiString(4);
		if (!"APS2".equals(identifier)) {
			throw new IOException("Unsupported Android relocation table format");
		}

		List<ElfRelocation> relocations = new ArrayList<>();

		try {
			int relocationIndex = 0;
			long remainingRelocations = LEB128.decode(reader, true);
			long offset = LEB128.decode(reader, true);
			long addend = 0;

			while (remainingRelocations > 0) {

				long groupSize = LEB128.decode(reader, true);
				if (groupSize > remainingRelocations) {
					Msg.warn(this, "Group relocation count " + groupSize +
						" exceeded total count " + remainingRelocations);
					break;
				}

				long groupFlags = LEB128.decode(reader, true);
				boolean groupedByInfo =
					(groupFlags & AndroidElfRelocationGroup.RELOCATION_GROUPED_BY_INFO_FLAG) != 0;
				boolean groupedByDelta = (groupFlags &
					AndroidElfRelocationGroup.RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) != 0;
				boolean groupedByAddend =
					(groupFlags & AndroidElfRelocationGroup.RELOCATION_GROUPED_BY_ADDEND_FLAG) != 0;
				boolean groupHasAddend =
					(groupFlags & AndroidElfRelocationGroup.RELOCATION_GROUP_HAS_ADDEND_FLAG) != 0;

				long groupOffsetDelta = groupedByDelta ? LEB128.decode(reader, true) : 0;
				long groupRInfo = groupedByInfo ? LEB128.decode(reader, true) : 0;

				if (groupedByAddend && groupHasAddend) {
					addend += LEB128.decode(reader, true);
				}

				for (int i = 0; i < groupSize; i++) {
					offset += groupedByDelta ? groupOffsetDelta : LEB128.decode(reader, true);

					long info = groupedByInfo ? groupRInfo : LEB128.decode(reader, true);

					long rAddend = 0;
					if (groupHasAddend) {
						if (!groupedByAddend) {
							addend += LEB128.decode(reader, true);
						}
						rAddend = addend;
					}

					relocations.add(ElfRelocation.createElfRelocation(reader.getFactory(),
						elfHeader, relocationIndex++, addendTypeReloc, offset, info, rAddend));
				}

				if (!groupHasAddend) {
					addend = 0;
				}

				remainingRelocations -= groupSize;
			}
		}
		catch (IOException e) {
			Msg.error(this, "Error reading relocations.", e);
		}

		return relocations;
	}

	/**
	 * @return true if has addend relocations, otherwise addend extraction from
	 * relocation target may be required
	 */
	public boolean hasAddendRelocations() {
		return addendTypeReloc;
	}

	/**
	 * Returns the section where the relocations will be applied.
	 * For example, this method will return ".plt" for ".rel.plt"
	 * @return the section where the relocations will be applied
	 * or null for dynamic relocation table not associated with 
	 * a section.
	 */
	public ElfSectionHeader getSectionToBeRelocated() {
		return sectionToBeRelocated;
	}

	/**
	 * Returns the relocations defined in this table.
	 * @return the relocations defined in this table
	 */
	public ElfRelocation[] getRelocations() {
		return relocs;
	}

	/**
	 * Get number of relocation entries contained within this table
	 * @return relocation entry count
	 */
	public int getRelocationCount() {
		return relocs.length;
	}

	/**
	 * Returns the associated symbol table.
	 * A relocation object contains a symbol index.
	 * This index is into this symbol table.
	 * @return the associated symbol table
	 */
	public ElfSymbolTable getAssociatedSymbolTable() {
		return symbolTable;
	}

	@Override
	public byte[] toBytes(DataConverter dc) {
		byte[] bytes = new byte[relocs.length * relocs[0].sizeof()];
		int index = 0;
		for (int i = 0; i < relocs.length; i++) {
			byte[] relocBytes = relocs[i].toBytes(dc);
			System.arraycopy(relocBytes, 0, bytes, index, relocBytes.length);
			index += relocBytes.length;
		}
		return bytes;
	}

	@Override
	public long getLength() {
		return length;
	}

	@Override
	public long getAddressOffset() {
		return addrOffset;
	}

	/**
	 * Get section header which corresponds to this table, or null
	 * if only associated with a dynamic table entry
	 * @return relocation table section header or null
	 */
	public ElfSectionHeader getTableSectionHeader() {
		return relocTableSection;
	}

	@Override
	public long getFileOffset() {
		return fileOffset;
	}

	@Override
	public int getEntrySize() {
		return (int) entrySize;
	}

	@Override
	public DataType toDataType() {
		if (format == TableFormat.ANDROID) {
			return new AndroidElfRelocationTableDataType();
		}

		ElfRelocation relocationRepresentative =
			ElfRelocation.createElfRelocation(factory, elfHeader, -1, addendTypeReloc, 0, 0, 0);
		DataType relocEntryDataType = relocationRepresentative.toDataType();
		return new ArrayDataType(relocEntryDataType, (int) (length / entrySize), (int) entrySize);
	}

}
