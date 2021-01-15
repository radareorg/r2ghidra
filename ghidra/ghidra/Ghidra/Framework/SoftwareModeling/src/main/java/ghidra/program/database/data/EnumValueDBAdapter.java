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
/*
 * Created on May 4, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package ghidra.program.database.data;

import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

/**
 * Adapter to access the Enumeration data type values tables.
 */
abstract class EnumValueDBAdapter {

	static final String ENUM_VALUE_TABLE_NAME = "Enumeration Values";
	static final Schema ENUM_VALUE_SCHEMA = EnumValueDBAdapterV0.V0_ENUM_VALUE_SCHEMA;
	// Enum Value Columns
	static final int ENUMVAL_NAME_COL = EnumValueDBAdapterV0.V0_ENUMVAL_NAME_COL;
	static final int ENUMVAL_VALUE_COL = EnumValueDBAdapterV0.V0_ENUMVAL_VALUE_COL;
	static final int ENUMVAL_ID_COL = EnumValueDBAdapterV0.V0_ENUMVAL_ID_COL;

	/**
	 * Gets an adapter for working with the enumeration data type values database table. The adapter is based 
	 * on the version of the database associated with the specified database handle and the openMode.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param monitor the monitor to use for displaying status or for canceling.
	 * @return the adapter for accessing the table of enumeration data type values.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is trouble accessing the database.
	 */
	static EnumValueDBAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		if (openMode == DBConstants.CREATE) {
			return new EnumValueDBAdapterV0(handle, true);
		}
		try {
			return new EnumValueDBAdapterV0(handle, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			EnumValueDBAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter);
			}
			return adapter;
		}
	}

	/**
	 * Tries to get a read only adapter for the database whose handle is passed to this method.
	 * @param handle handle to prior version of the database.
	 * @return the read only Enumeration Data Type Values table adapter
	 * @throws VersionException if a read only adapter can't be obtained for the database handle's version.
	 */
	static EnumValueDBAdapter findReadOnlyAdapter(DBHandle handle) {
		return new EnumValueDBAdapterNoTable(handle);
	}

	/**
	 * Upgrades the Enumeration Data Type Values table from the oldAdapter's version to the current version.
	 * @param handle handle to the database whose table is to be upgraded to a newer version.
	 * @param oldAdapter the adapter for the existing table to be upgraded.
	 * @return the adapter for the new upgraded version of the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if the database can't be read or written.
	 */
	static EnumValueDBAdapter upgrade(DBHandle handle, EnumValueDBAdapter oldAdapter)
			throws VersionException, IOException {
		return new EnumValueDBAdapterV0(handle, true);
	}

	abstract void createRecord(long enumID, String name, long value) throws IOException;

	abstract Record getRecord(long valueID) throws IOException;

	/**
	 * Remove the record for the given enum Value ID.
	 * @param valueID ID of the value record to delete
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void removeRecord(long valueID) throws IOException;

	/**
	 * Updates the enum data type values table with the provided record.
	 * @param record the new record
	 * @throws IOException if the database can't be accessed.
	 */
	abstract void updateRecord(Record record) throws IOException;

	abstract long[] getValueIdsInEnum(long enumID) throws IOException;

}
