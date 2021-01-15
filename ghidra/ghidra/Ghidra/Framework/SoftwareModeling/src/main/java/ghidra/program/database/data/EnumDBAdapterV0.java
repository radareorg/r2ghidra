/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.database.data;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

/**
 * Version 0 implementation for accessing the Enumeration database table. 
 */
class EnumDBAdapterV0 extends EnumDBAdapter implements RecordTranslator {
	static final int VERSION = 0;

	// Enum Columns
	static final int V0_ENUM_NAME_COL = 0;
	static final int V0_ENUM_COMMENT_COL = 1;
	static final int V0_ENUM_CAT_COL = 2;
	static final int V0_ENUM_SIZE_COL = 3;

	static final Schema V0_ENUM_SCHEMA = new Schema(VERSION, "Enum ID", new Class[] {
		StringField.class, StringField.class, LongField.class, ByteField.class }, new String[] {
		"Name", "Comment", "Category ID", "Size" });

	private Table enumTable;

	/**
	 * Gets a version 0 adapter for the Enumeration database table.
	 * @param handle handle to the database containing the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public EnumDBAdapterV0(DBHandle handle) throws VersionException {

		enumTable = handle.getTable(ENUM_TABLE_NAME);
		if (enumTable == null) {
			throw new VersionException("Missing Table: " + ENUM_TABLE_NAME);
		}
		int version = enumTable.getSchema().getVersion();
		if (version != VERSION) {
			String msg =
				"Expected version " + VERSION + " for table " + ENUM_TABLE_NAME + " but got " +
					enumTable.getSchema().getVersion();
			if (version < VERSION) {
				throw new VersionException(msg, VersionException.OLDER_VERSION, true);
			}
			throw new VersionException(msg, VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	public Record createRecord(String name, String comments, long categoryID, byte size,
			long sourceArchiveID, long sourceDataTypeID, long lastChangeTime) throws IOException {
		throw new UnsupportedOperationException("Not allowed to update prior version #" + VERSION +
			" of " + ENUM_TABLE_NAME + " table.");
	}

	@Override
	public Record getRecord(long enumID) throws IOException {
		return translateRecord(enumTable.getRecord(enumID));
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(enumTable.iterator(), this);
	}

	@Override
	public void updateRecord(Record record, boolean setLastChangeTime) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeRecord(long enumID) throws IOException {
		// TODO make sure that the enum value records are getting deleted in the datatype manager.
		return enumTable.deleteRecord(enumID);
	}

	@Override
	protected void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(ENUM_TABLE_NAME);
	}

	@Override
	public long[] getRecordIdsInCategory(long categoryID) throws IOException {
		return enumTable.findRecords(new LongField(categoryID), V0_ENUM_CAT_COL);
	}

	@Override
	long[] getRecordIdsForSourceArchive(long archiveID) throws IOException {
		return new long[0];
	}

	/* (non-Javadoc)
	 * @see db.RecordTranslator#translateRecord(db.Record)
	 */
	public Record translateRecord(Record oldRec) {
		if (oldRec == null) {
			return null;
		}
		Record rec = EnumDBAdapter.ENUM_SCHEMA.createRecord(oldRec.getKey());
		rec.setString(ENUM_NAME_COL, oldRec.getString(V0_ENUM_NAME_COL));
		rec.setString(ENUM_COMMENT_COL, oldRec.getString(V0_ENUM_COMMENT_COL));
		rec.setLongValue(ENUM_CAT_COL, oldRec.getLongValue(V0_ENUM_CAT_COL));
		rec.setByteValue(ENUM_SIZE_COL, oldRec.getByteValue(V0_ENUM_SIZE_COL));
		rec.setLongValue(ENUM_SOURCE_ARCHIVE_ID_COL, DataTypeManager.LOCAL_ARCHIVE_KEY);
		rec.setLongValue(ENUM_UNIVERSAL_DT_ID_COL, UniversalIdGenerator.nextID().getValue());
		rec.setLongValue(ENUM_SOURCE_SYNC_TIME_COL, DataType.NO_SOURCE_SYNC_TIME);
		rec.setLongValue(ENUM_LAST_CHANGE_TIME_COL, DataType.NO_LAST_CHANGE_TIME);
		return rec;
	}

	@Override
	Record getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		return null;
	}

//	private void testVersion(Table table, int expectedVersion, String name)
//			throws DatabaseVersionException {
//				
//		if (table == null) {
//			throw new DatabaseVersionException(name+ " not found");
//		}
//		int versionNumber = table.getSchema().getVersion();
//		if (versionNumber != expectedVersion) {
//			throw new DatabaseVersionException(
//				name+": Expected Version "+expectedVersion+ ", got " + versionNumber);
//		}
//	}
}
