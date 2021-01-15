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
 * 
 * 
 */
class OldStackVariableDBAdapterV1 extends OldStackVariableDBAdapter {

	static final String STACK_VARS_TABLE_NAME = "Stack Variables";

	final static int SCHEMA_VERSION = 1;

	// Stack Variables Table Columns
	static final int V1_STACK_VAR_FUNCTION_KEY_COL = 0;
	static final int V1_STACK_VAR_OFFSET_COL = 1;
	static final int V1_STACK_VAR_DATA_TYPE_ID_COL = 2;
	static final int V1_STACK_VAR_NAME_COL = 3;
	static final int V1_STACK_VAR_COMMENT_COL = 4;
	static final int V1_STACK_VAR_DT_LENGTH_COL = 5;

	static final Schema V1_STACK_VARS_SCHEMA = new Schema(SCHEMA_VERSION, "Key", new Class[] {
		LongField.class, IntField.class, LongField.class, StringField.class, StringField.class,
		IntField.class },

	new String[] { "Function ID", "Offset", "DataType ID", "Name", "Comment", "DataType Length" });

	private Table table;

	OldStackVariableDBAdapterV1(DBHandle dbHandle, AddressMap addrMap) throws VersionException {

		table = dbHandle.getTable(STACK_VARS_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + STACK_VARS_TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != SCHEMA_VERSION) {
			int version = table.getSchema().getVersion();
			if (version < SCHEMA_VERSION) {
				throw new VersionException(true);
			}
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	/**
	 * @see ghidra.program.database.function.FunctionDBAdapter#getStackVariableRecord(long)
	 */
	@Override
	public Record getStackVariableRecord(long key) throws IOException {
		return table.getRecord(key);
	}

	/**
	 * @see ghidra.program.database.function.FunctionDBAdapter#getStackVariableKeys(long)
	 */
	@Override
	public long[] getStackVariableKeys(long functionKey) throws IOException {
		return table.findRecords(new LongField(functionKey), V1_STACK_VAR_FUNCTION_KEY_COL);
	}

	/**
	 * @see ghidra.program.database.data.PointerDBAdapter#deleteTable()
	 */
	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(STACK_VARS_TABLE_NAME);
	}

}
