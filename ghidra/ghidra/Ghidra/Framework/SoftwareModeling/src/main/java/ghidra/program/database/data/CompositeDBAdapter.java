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
package ghidra.program.database.data;

import java.io.IOException;

import db.*;
import ghidra.util.UniversalID;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the Composite database table.
 */
abstract class CompositeDBAdapter {

	static final String COMPOSITE_TABLE_NAME = "Composite Data Types";
	static final Schema COMPOSITE_SCHEMA = CompositeDBAdapterV2V3.V2_COMPOSITE_SCHEMA;

	static final int COMPOSITE_NAME_COL = CompositeDBAdapterV2V3.V2_COMPOSITE_NAME_COL;
	static final int COMPOSITE_COMMENT_COL = CompositeDBAdapterV2V3.V2_COMPOSITE_COMMENT_COL;
	static final int COMPOSITE_IS_UNION_COL = CompositeDBAdapterV2V3.V2_COMPOSITE_IS_UNION_COL;
	static final int COMPOSITE_CAT_COL = CompositeDBAdapterV2V3.V2_COMPOSITE_CAT_COL;
	static final int COMPOSITE_LENGTH_COL = CompositeDBAdapterV2V3.V2_COMPOSITE_LENGTH_COL;
	static final int COMPOSITE_NUM_COMPONENTS_COL =
		CompositeDBAdapterV2V3.V2_COMPOSITE_NUM_COMPONENTS_COL;
	static final int COMPOSITE_SOURCE_ARCHIVE_ID_COL =
		CompositeDBAdapterV2V3.V2_COMPOSITE_SOURCE_ARCHIVE_ID_COL;
	static final int COMPOSITE_UNIVERSAL_DT_ID =
		CompositeDBAdapterV2V3.V2_COMPOSITE_UNIVERSAL_DT_ID_COL;
	static final int COMPOSITE_SOURCE_SYNC_TIME_COL =
		CompositeDBAdapterV2V3.V2_COMPOSITE_SOURCE_SYNC_TIME_COL;
	static final int COMPOSITE_LAST_CHANGE_TIME_COL =
		CompositeDBAdapterV2V3.V2_COMPOSITE_LAST_CHANGE_TIME_COL;
	static final int COMPOSITE_INTERNAL_ALIGNMENT_COL =
		CompositeDBAdapterV2V3.V2_COMPOSITE_INTERNAL_ALIGNMENT_COL;
	static final int COMPOSITE_EXTERNAL_ALIGNMENT_COL =
		CompositeDBAdapterV2V3.V2_COMPOSITE_EXTERNAL_ALIGNMENT_COL;

	// Internal Alignment Constants
	static final byte UNALIGNED = (byte) -1;
	static final byte ALIGNED_NO_PACKING = (byte) 0;
	// Otherwise the packing value.

	// External Alignment Constants
	static final byte MACHINE_ALIGNED = (byte) -1;
	static final byte DEFAULT_ALIGNED = (byte) 0;

	// Otherwise the external minimum alignment value.

	/**
	 * Gets an adapter for working with the composite data type database table. 
	 * The composite table is used to store structures and unions. The adapter is based 
	 * on the version of the database associated with the specified database handle and the openMode.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param monitor the monitor to use for displaying status or for canceling.
	 * @return the adapter for accessing the table of composite data types.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is trouble accessing the database.
	 * @throws CancelledException task cancelled
	 */
	static CompositeDBAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		try {
			return new CompositeDBAdapterV2V3(handle, openMode);
		}
		catch (VersionException e) {
			if (openMode == DBConstants.CREATE) {
				throw new AssertException();
			}
			if (openMode == DBConstants.UPGRADE) {
				CompositeDBAdapter adapter = findReadOnlyAdapter(handle);
				return upgrade(handle, adapter, monitor);
			}
			throw e;
		}
	}

	/**
	 * Tries to get a read only adapter for the database whose handle is passed to this method.
	 * @param handle handle to prior version of the database.
	 * @return the read only Composite data type table adapter
	 * @throws VersionException if a read only adapter can't be obtained for the database handle's version.
	 * @throws IOException 
	 */
	static CompositeDBAdapter findReadOnlyAdapter(DBHandle handle)
			throws VersionException, IOException {
		try {
			return new CompositeDBAdapterV2V3(handle);
		}
		catch (VersionException e) {
			// ignore
		}
		try {
			return new CompositeDBAdapterV1(handle);
		}
		catch (VersionException e) {
			// ignore
		}
		return new CompositeDBAdapterV0(handle);
	}

	/**
	 * Upgrades the Composite data type table from the oldAdapter's version to the current version.
	 * @param handle handle to the database whose table is to be upgraded to a newer version.
	 * @param oldAdapter the adapter for the existing table to be upgraded.
	 * @param monitor task monitor
	 * @return the adapter for the new upgraded version of the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if the database can't be read or written.
	 * @throws CancelledException user cancelled upgrade
	 */
	static CompositeDBAdapter upgrade(DBHandle handle, CompositeDBAdapter oldAdapter,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {

		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		CompositeDBAdapter tmpAdapter = null;
		try {
			tmpAdapter = new CompositeDBAdapterV2V3(tmpHandle, DBConstants.CREATE);
			RecordIterator it = oldAdapter.getRecords();
			while (it.hasNext()) {
				monitor.checkCanceled();
				Record rec = it.next();
				tmpAdapter.updateRecord(rec, false);
			}
			oldAdapter.deleteTable(handle);
			CompositeDBAdapter newAdapter = new CompositeDBAdapterV2V3(handle, DBConstants.CREATE);
			it = tmpAdapter.getRecords();
			while (it.hasNext()) {
				monitor.checkCanceled();
				Record rec = it.next();
				newAdapter.updateRecord(rec, false);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.endTransaction(id, true);
			tmpHandle.close();
		}
	}

	/**
	 * Creates a database record for a composite data type (structure or union).
	 * @param name the unique name for this data type
	 * @param comments comments about this data type
	 * @param isUnion true indicates this data type is a union and all component offsets are at zero.
	 * @param categoryID the ID for the category that contains this array.
	 * @param length the total length or size of this data type.
	 * @param sourceArchiveID the ID for the source archive where this data type originated.
	 * @param sourceDataTypeID the ID of the associated data type in the source archive.
	 * @param lastChangeTime the time this data type was last changed.
	 * @param internalAlignment UNALIGNED, ALIGNED_NO_PACKING or the packing value 
	 * currently in use by this data type.
	 * @param externalAlignment DEFAULT_ALIGNED, MACHINE_ALIGNED or the minimum alignment value 
	 * currently in use by this data type. 
	 * @return the database record for this data type.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract Record createRecord(String name, String comments, boolean isUnion, long categoryID,
			int length, long sourceArchiveID, long sourceDataTypeID, long lastChangeTime,
			int internalAlignment, int externalAlignment) throws IOException;

	/**
	 * Gets a composite data type record from the database based on its ID.
	 * @param dataTypeID the data type's ID.
	 * @return the record for the composite (structure or union) data type.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract Record getRecord(long dataTypeID) throws IOException;

	/**
	 * Gets an iterator over all composite (structure and union) data type records.
	 * @return the composite data type record iterator.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Updates the composite data type table with the provided record.
	 * @param record the new record
	 * @param setLastChangedTime true means change the last change time in the record to the 
	 * current time before putting the record in the database.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void updateRecord(Record record, boolean setLastChangeTime) throws IOException;

	/**
	 * Removes the composite data type record with the specified ID.
	 * @param dataID the ID of the data type.
	 * @return true if the record is removed.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract boolean removeRecord(long dataID) throws IOException;

	/**
	 * Deletes the composite data type table from the database with the specified database handle.
	 * @param handle handle to the database where the table should get deleted.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void deleteTable(DBHandle handle) throws IOException;

	/**
	 * Gets all the composite data types that are contained in the category that has the indicated ID.
	 * @param categoryID the category whose composite data types are wanted.
	 * @return an array of IDs for the composite data types in the category.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract long[] getRecordIdsInCategory(long categoryID) throws IOException;

	/**
	 * Gets an array with the IDs of all data types in the composite table that were derived
	 * from the source data type archive indicated by the source archive ID.
	 * @param archiveID the ID of the source archive whose data types we want.
	 * @return the array data type IDs.
	 * @throws IOException if the database can't be accessed.
	 */
	abstract long[] getRecordIdsForSourceArchive(long archiveID) throws IOException;

	abstract Record getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID)
			throws IOException;

}
