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
package ghidra.feature.vt.api.db;

import static ghidra.feature.vt.api.db.VTAssociationTableDBAdapter.AssociationTableDescriptor.INSTANCE;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.Set;

import db.*;
import db.util.TableColumn;

public abstract class VTAssociationTableDBAdapter {

	public static class AssociationTableDescriptor extends db.util.TableDescriptor {

		public static TableColumn SOURCE_ADDRESS_COL = new TableColumn(LongField.class, true);
		public static TableColumn DESTINATION_ADDRESS_COL = new TableColumn(LongField.class, true);
		public static TableColumn TYPE_COL = new TableColumn(ByteField.class);
		public static TableColumn STATUS_COL = new TableColumn(ByteField.class);
		public static TableColumn APPLIED_STATUS_COL = new TableColumn(ByteField.class);
		public static TableColumn VOTE_COUNT_COL = new TableColumn(IntField.class);

		public static AssociationTableDescriptor INSTANCE = new AssociationTableDescriptor();
	}

	static String TABLE_NAME = "AssociationTable";
	static Schema TABLE_SCHEMA =
		new Schema(0, "Key", INSTANCE.getColumnClasses(), INSTANCE.getColumnNames());
	static int[] TABLE_INDEXES = INSTANCE.getIndexedColumns();

	public static VTAssociationTableDBAdapter createAdapter(DBHandle dbHandle) throws IOException {
		return new VTAssociationTableDBAdapterV0(dbHandle);
	}

	static VTAssociationTableDBAdapter getAdapter(DBHandle dbHandle, OpenMode openMode,
			TaskMonitor monitor) throws VersionException {
		return new VTAssociationTableDBAdapterV0(dbHandle, openMode, monitor);
	}

	abstract Record insertRecord(long sourceAddressID, long destinationAddressID,
			VTAssociationType type, VTAssociationStatus status, int voteCount) throws IOException;

	abstract void deleteRecord(long sourceAddressID) throws IOException;

	abstract RecordIterator getRecordsForSourceAddress(long sourceAddressID) throws IOException;

	abstract RecordIterator getRecordsForDestinationAddress(long destinationAddressID)
			throws IOException;

	abstract int getRecordCount();

	abstract RecordIterator getRecords() throws IOException;

	abstract Record getRecord(long key) throws IOException;

	abstract Set<Record> getRelatedAssociationRecordsBySourceAndDestinationAddress(
			long sourceAddressID, long destinationAddressID) throws IOException;

	abstract Set<Record> getRelatedAssociationRecordsBySourceAddress(long sourceAddressID)
			throws IOException;

	abstract Set<Record> getRelatedAssociationRecordsByDestinationAddress(long destinationAddressID)
			throws IOException;

	abstract void updateRecord(Record record) throws IOException;

	abstract void removeAssociaiton(long id) throws IOException;
}
