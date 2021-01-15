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
package ghidra.program.database.oldfunction;

import ghidra.program.database.map.AddressMap;
import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

/**
 * Database adapter for stack variables.
 *
 * 
 */
abstract class OldStackVariableDBAdapter {
	static final Schema STACK_VARS_SCHEMA = OldStackVariableDBAdapterV1.V1_STACK_VARS_SCHEMA;
	// Stack Variables Table Columns
	static final int STACK_VAR_FUNCTION_KEY_COL =
		OldStackVariableDBAdapterV1.V1_STACK_VAR_FUNCTION_KEY_COL;
	static final int STACK_VAR_OFFSET_COL = OldStackVariableDBAdapterV1.V1_STACK_VAR_OFFSET_COL;
	static final int STACK_VAR_DATA_TYPE_ID_COL =
		OldStackVariableDBAdapterV1.V1_STACK_VAR_DATA_TYPE_ID_COL;
	static final int STACK_VAR_NAME_COL = OldStackVariableDBAdapterV1.V1_STACK_VAR_NAME_COL;
	static final int STACK_VAR_COMMENT_COL = OldStackVariableDBAdapterV1.V1_STACK_VAR_COMMENT_COL;
	static final int STACK_VAR_DT_LENGTH_COL =
		OldStackVariableDBAdapterV1.V1_STACK_VAR_DT_LENGTH_COL;

	static OldStackVariableDBAdapter getAdapter(DBHandle handle, AddressMap map)
			throws VersionException {

		try {
			return new OldStackVariableDBAdapterV1(handle, map);
		}
		catch (VersionException e) {
			if (!e.isUpgradable()) {
				throw e;
			}
		}
		return new OldStackVariableDBAdapterV0(handle, map);
	}

	/**
	 * 
	 */
	abstract void deleteTable(DBHandle handle) throws IOException;

	/**
	 * Get a stack variable record.
	 * @param key
	 * @return Record
	 */
	abstract Record getStackVariableRecord(long key) throws IOException;

	/**
	 * Get all stack variable keys which correspond to a function.
	 * @param functionKey
	 * @return array of stack variable keys.
	 * @throws IOException
	 */
	abstract long[] getStackVariableKeys(long functionKey) throws IOException;

}
