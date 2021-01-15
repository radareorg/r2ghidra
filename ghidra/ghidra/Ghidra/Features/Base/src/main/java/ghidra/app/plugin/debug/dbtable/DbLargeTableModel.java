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
package ghidra.app.plugin.debug.dbtable;

import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

import java.io.IOException;
import java.util.*;

import javax.swing.event.TableModelListener;
import javax.swing.table.TableModel;

import db.*;

public class DbLargeTableModel implements TableModel {
	private ArrayList<TableModelListener> listeners = new ArrayList<TableModelListener>();
	private Table table;
	private Schema schema;
	private List<AbstractColumnAdapter> columns = new ArrayList<AbstractColumnAdapter>();
	private RecordIterator recIt;
	private Record lastRecord;
	private int lastIndex;
	private Field minKey;
	private Field maxKey;
	private Field keyType;

	public DbLargeTableModel(Table table) {
		this.table = table;
		schema = table.getSchema();
		try {
			keyType = schema.getKeyFieldClass().newInstance();
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		try {
			recIt = table.iterator();
			lastRecord = recIt.next();
			lastIndex = 0;
			findMaxKey();
			findMinKey();
		}
		catch (IOException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}

		columns.add(getColumn(schema.getKeyFieldClass()));

		Class<?>[] classes = schema.getFieldClasses();
		int fieldCount = schema.getFieldCount();
		for (int i = 0; i < fieldCount; i++) {
			columns.add(getColumn(classes[i]));
		}

	}

	private AbstractColumnAdapter getColumn(Class<?> c) {
		if (c == ByteField.class) {
			return new ByteColumnAdapter();
		}
		else if (c == BooleanField.class) {
			return new BooleanColumnAdapter();
		}
		else if (c == ShortField.class) {
			return new ShortColumnAdapter();
		}
		else if (c == IntField.class) {
			return new IntegerColumnAdapter();
		}
		else if (c == LongField.class) {
			return new LongColumnAdapter();
		}
		else if (c == StringField.class) {
			return new StringColumnAdapter();
		}
		else if (c == BinaryField.class) {
			return new BinaryColumnAdapter();
		}
		throw new AssertException("New, unexpected DB column class type: " + c);
	}

	private void findMinKey() throws IOException {
		RecordIterator iter = table.iterator();
		Record rec = iter.next();
		minKey = rec.getKeyField();
	}

	private void findMaxKey() throws IOException {
		Field max = keyType.newField();
		if (table.useLongKeys()) {
			max.setLongValue(Long.MAX_VALUE);
		}
		else {
			byte[] maxBytes = new byte[128];
			Arrays.fill(maxBytes, 0, 128, (byte) 0x7f);
			max.setBinaryData(maxBytes);
		}
		RecordIterator iter = table.iterator(max);
		Record rec = iter.previous();
		maxKey = rec.getKeyField();
	}

	@Override
	public void addTableModelListener(TableModelListener l) {
		listeners.add(l);
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return columns.get(columnIndex).getValueClass();
	}

	@Override
	public int getColumnCount() {
		return schema.getFieldCount() + 1;
	}

	@Override
	public String getColumnName(int columnIndex) {
		if (columnIndex == 0) {
			return schema.getKeyName();
		}
		--columnIndex;
		int[] indexCols = table.getIndexedColumns();
		boolean isIndexed = false;
		for (int i = 0; i < indexCols.length; i++) {
			if (indexCols[i] == columnIndex) {
				isIndexed = true;
				break;
			}
		}
		return schema.getFieldNames()[columnIndex] + (isIndexed ? "*" : "");
	}

	@Override
	public int getRowCount() {
		return table.getRecordCount();
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		Record rec = getRecord(rowIndex);
		if (columnIndex == 0) { // key column
			return columns.get(columnIndex).getKeyValue(rec);
		}

		int dbColumn = columnIndex - 1; // -1, since the DB indices do not have the key column included
		return columns.get(columnIndex).getValue(rec, dbColumn);
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	@Override
	public void removeTableModelListener(TableModelListener l) {
		listeners.remove(l);

	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		// no!
	}

	private Record getRecord(int index) {
		try {
			if (index == lastIndex + 1) {
				if (recIt.hasNext()) {
					lastRecord = recIt.next();
					lastIndex = index;
				}
				else {
					// iterator ran out
				}
			}
			else if (index != lastIndex) {
				if (index < lastIndex && (lastIndex - index) < 200) {
					int backup = lastIndex - index + 1;
					for (int i = 0; i < backup; i++) {
						if (recIt.hasPrevious()) {
							recIt.previous();
						}
					}
					Record rec = recIt.next();
					if (rec != null) {
						lastRecord = rec;
						lastIndex = index;
					}
				}
				else {
					findRecord(index);
					lastRecord = recIt.next();
					lastIndex = index;
				}
			}
		}
		catch (IOException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}

		return lastRecord;
	}

	private void findRecord(int index) throws IOException {
		if (index < 1000) {
			recIt = table.iterator();
			for (int i = 0; i < index; i++) {
				recIt.next();
			}
		}
		else if (index > table.getRecordCount() - 1000) {
			recIt = table.iterator(maxKey);
			if (recIt.hasNext()) {
				recIt.next();
			}
			for (int i = 0; i < table.getRecordCount() - index; i++) {
				recIt.previous();
			}
		}
		else {
			recIt = table.iterator(approxKey(index));
		}
	}

	private Field approxKey(int index) {
		Field key = keyType.newField();
		if (table.useLongKeys()) {
			long min = minKey.getLongValue();
			long max = maxKey.getLongValue();
			long k = min + ((max - min) * index / table.getRecordCount());
			key.setLongValue(k);
		}
		else {
			long min = getLong(minKey.getBinaryData());
			long max = getLong(maxKey.getBinaryData());
			long k = min + ((max - min) * index / table.getRecordCount());
			byte[] bytes = new byte[8];
			for (int i = 7; i >= 0; i--) {
				bytes[i] = (byte) k;
				k >>= 8;
			}
			key.setBinaryData(bytes);
		}
		return key;
	}

	private long getLong(byte[] bytes) {
		if (bytes == null || bytes.length == 0)
			return 0;
		long value = 0;
		for (int i = 0; i < 8; i++) {
			value <<= 8;
			if (i < bytes.length) {
				value += bytes[i] & 0xff;
			}
		}
		return value;
	}
}
