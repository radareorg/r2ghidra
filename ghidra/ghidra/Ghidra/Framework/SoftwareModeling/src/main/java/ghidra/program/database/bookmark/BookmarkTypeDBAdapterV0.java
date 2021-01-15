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
package ghidra.program.database.bookmark;

import ghidra.util.exception.VersionException;

import java.io.IOException;
import java.util.ArrayList;

import db.*;

public class BookmarkTypeDBAdapterV0 extends BookmarkTypeDBAdapter {

	private Table table;

	public BookmarkTypeDBAdapterV0(DBHandle dbHandle, boolean create) throws VersionException,
			IOException {
		if (create) {
			table = dbHandle.createTable(TABLE_NAME, SCHEMA);
		}
		else {
			table = dbHandle.getTable(TABLE_NAME);
			if (table == null) {
				throw new VersionException(true);
			}
			else if (table.getSchema().getVersion() != 0) {
				throw new VersionException(false);
			}
		}
	}

	@Override
	Record[] getRecords() throws IOException {
		ArrayList<Record> list = new ArrayList<Record>();
		RecordIterator iter = table.iterator();
		while (iter.hasNext()) {
			list.add(iter.next());
		}
		Record[] recs = new Record[list.size()];
		list.toArray(recs);
		return recs;
	}

	@Override
	void addType(int typeId, String type) throws IOException {

		Record rec = SCHEMA.createRecord(typeId);
		rec.setString(TYPE_NAME_COL, type);
		table.putRecord(rec);
	}

	@Override
	void deleteRecord(long typeId) throws IOException {
		table.deleteRecord(typeId);
	}
}
