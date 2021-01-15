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

import ghidra.program.database.map.AddressMap;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

/**
 * Adapter to access the Pointer database table for Pointer data types.
 * 
 */
abstract class PointerDBAdapter {
	static final String POINTER_TABLE_NAME = "Pointers";

	static final Schema SCHEMA = new Schema(PointerDBAdapterV2.VERSION, "Pointer ID", new Class[] {
		LongField.class, LongField.class, ByteField.class }, new String[] { "Data Type ID",
		"Category ID", "Length" });

	static final int PTR_DT_ID_COL = 0;
	static final int PTR_CATEGORY_COL = 1;
	static final int PTR_LENGTH_COL = 2;

	static PointerDBAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor,
			AddressMap addrMap) throws VersionException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new PointerDBAdapterV2(handle, true);
		}
		try {
			return new PointerDBAdapterV2(handle, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			PointerDBAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter, monitor);
			}
			return adapter;
		}
	}

	static PointerDBAdapter findReadOnlyAdapter(DBHandle handle) throws VersionException {
		try {
			return new PointerDBAdapterV1(handle);
		}
		catch (VersionException e) {
			return new PointerDBAdapterV0(handle);
		}
	}

	static PointerDBAdapter upgrade(DBHandle handle, PointerDBAdapter oldAdapter,
			TaskMonitor monitor) throws VersionException, IOException {

		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		PointerDBAdapter tmpAdapter = null;
		try {
			tmpAdapter = new PointerDBAdapterV2(tmpHandle, true);
			RecordIterator it = oldAdapter.getRecords();
			while (it.hasNext()) {
				Record rec = it.next();
				tmpAdapter.updateRecord(rec);
			}
			oldAdapter.deleteTable(handle);
			PointerDBAdapter newAdapter = new PointerDBAdapterV2(handle, true);
			it = tmpAdapter.getRecords();
			while (it.hasNext()) {
				Record rec = it.next();
				newAdapter.updateRecord(rec);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.endTransaction(id, true);
			tmpHandle.close();
		}
	}

	/**
	 * 
	 */
	abstract void deleteTable(DBHandle handle) throws IOException;

	/**
	 * Create a pointer record.
	 * @param dataTypeID data type ID of the date type being pointed to
	 * @param categoryID the category ID of the datatype
	 * @param length pointer size in bytes
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract Record createRecord(long dataTypeID, long categoryID, int length) throws IOException;

	/**
	 * Get the record with the given pointerID.
	 * @param pointerID database key
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract Record getRecord(long pointerID) throws IOException;

	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Delete the record.
	 * @param pointerID database key
	 * @return true if the record was deleted
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean removeRecord(long pointerID) throws IOException;

	/**
	 * Update the record in the table.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateRecord(Record record) throws IOException;

	abstract long[] getRecordIdsInCategory(long categoryID) throws IOException;

	Record translateRecord(Record rec) {
		return rec;
	}

	class TranslatedRecordIterator implements RecordIterator {
		private RecordIterator it;

		TranslatedRecordIterator(RecordIterator it) {
			this.it = it;
		}

		public boolean delete() throws IOException {
			throw new UnsupportedOperationException();
		}

		public boolean hasNext() throws IOException {
			return it.hasNext();
		}

		public boolean hasPrevious() throws IOException {
			return it.hasPrevious();
		}

		public Record next() throws IOException {
			Record rec = it.next();
			return translateRecord(rec);
		}

		public Record previous() throws IOException {
			Record rec = it.previous();
			return translateRecord(rec);
		}
	}

}
