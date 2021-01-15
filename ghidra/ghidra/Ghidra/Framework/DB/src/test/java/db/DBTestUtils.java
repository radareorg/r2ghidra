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
package db;

import java.io.File;
import java.io.IOException;
import java.util.Random;

import org.junit.Assert;

import db.buffers.BufferFileManager;
import db.buffers.DummyBufferFileMgr;

/**
 *
 */
public class DBTestUtils {

	// Schema Types
	static final int EMPTY = 0;
	static final int SINGLE_BYTE = 1;
	static final int SINGLE_INT = 2;
	static final int SINGLE_SHORT = 3;
	static final int SINGLE_LONG = 4;
	static final int SINGLE_STRING = 5;
	static final int SINGLE_BINARY = 6;
	static final int ALL_TYPES = 7;

	static final int MAX_SCHEMA_TYPE = 7;

	private static Class<?>[][] schemaFields = { {}, // no columns
		{ ByteField.class }, { IntField.class }, { ShortField.class }, { LongField.class },
		{ StringField.class }, { BinaryField.class }, { ByteField.class, IntField.class,
			ShortField.class, LongField.class, StringField.class, BinaryField.class } };

	private static String[][] schemaFieldNames = { {}, // no columns
		{ "Byte" }, { "Int" }, { "Short" }, { "Long" }, { "String" }, { "Binary" },
		{ "Byte", "Int", "Short", "Long", "String", "Binary" } };

	private static Schema[] longKeySchemas =
		{ new Schema(0, "LongKey", schemaFields[0], schemaFieldNames[0]),
			new Schema(0, "LongKey", schemaFields[1], schemaFieldNames[1]),
			new Schema(0, "LongKey", schemaFields[2], schemaFieldNames[2]),
			new Schema(0, "LongKey", schemaFields[3], schemaFieldNames[3]),
			new Schema(0, "LongKey", schemaFields[4], schemaFieldNames[4]),
			new Schema(0, "LongKey", schemaFields[5], schemaFieldNames[5]),
			new Schema(0, "LongKey", schemaFields[6], schemaFieldNames[6]),
			new Schema(0, "LongKey", schemaFields[7], schemaFieldNames[7]) };

	private static Field varKeyType = new BinaryField();
	private static Class<? extends Field> varKeyClass = varKeyType.getClass();

	private static Schema[] binaryKeySchemas =
		{ new Schema(0, varKeyClass, "VarKey", schemaFields[0], schemaFieldNames[0]),
			new Schema(0, varKeyClass, "VarKey", schemaFields[1], schemaFieldNames[1]),
			new Schema(0, varKeyClass, "VarKey", schemaFields[2], schemaFieldNames[2]),
			new Schema(0, varKeyClass, "VarKey", schemaFields[3], schemaFieldNames[3]),
			new Schema(0, varKeyClass, "VarKey", schemaFields[4], schemaFieldNames[4]),
			new Schema(0, varKeyClass, "VarKey", schemaFields[5], schemaFieldNames[5]),
			new Schema(0, varKeyClass, "VarKey", schemaFields[6], schemaFieldNames[6]),
			new Schema(0, varKeyClass, "VarKey", schemaFields[7], schemaFieldNames[7]) };

	static Random random = new Random(0x123456789L);

	/**
	 * Create a new long-keyed table within the specified database.
	 * @param db database handle
	 * @param name name of table
	 * @param schemaType type of schema (use static identifier)
	 * @param createIndex all fields will be indexed if true
	 * @return Table new table
	 * @throws IOException
	 */
	static Table createLongKeyTable(DBHandle db, String name, int schemaType, boolean createIndex)
			throws IOException {
		Table t;
		int indexCnt = 0;
		if (createIndex) {
			indexCnt = schemaFields[schemaType].length;
			int[] indexedColumns = new int[indexCnt];
			for (int i = 0; i < indexedColumns.length; i++) {
				indexedColumns[i] = i;
			}
			t = db.createTable(name, longKeySchemas[schemaType], indexedColumns);
		}
		else {
			t = db.createTable(name, longKeySchemas[schemaType]);
		}
		Assert.assertEquals(name, t.getName());
		Assert.assertEquals(indexCnt, t.getIndexedColumns().length);
		Assert.assertEquals(Long.MIN_VALUE, t.getMaxKey());
		Assert.assertEquals(0, t.getRecordCount());
		Assert.assertEquals(longKeySchemas[schemaType], t.getSchema());
		Assert.assertTrue(t.useLongKeys());
		return t;
	}

	/**
	 * Create a new BinaryField-keyed table within the specified database.
	 * @param db database handle
	 * @param name name of table
	 * @param schemaType type of schema (use static identifier)
	 * @param createIndex all fields will be indexed if true
	 * @return Table new table
	 * @throws IOException
	 */
	static Table createBinaryKeyTable(DBHandle db, String name, int schemaType, boolean createIndex)
			throws IOException {
		Table t;
		int indexCnt = 0;
		if (createIndex) {
			indexCnt = schemaFields[schemaType].length;
			int[] indexedColumns = new int[indexCnt];
			for (int i = 0; i < indexedColumns.length; i++) {
				indexedColumns[i] = i;
			}
			t = db.createTable(name, binaryKeySchemas[schemaType], indexedColumns);
		}
		else {
			t = db.createTable(name, binaryKeySchemas[schemaType]);
		}
		Assert.assertEquals(name, t.getName());
		Assert.assertEquals(indexCnt, t.getIndexedColumns().length);
		Assert.assertEquals(Long.MIN_VALUE, t.getMaxKey());
		Assert.assertEquals(0, t.getRecordCount());
		Assert.assertEquals(binaryKeySchemas[schemaType], t.getSchema());
		Assert.assertTrue(!t.useLongKeys());
		return t;
	}

	static String[] getFieldNames(int schemaType) {
		return schemaFieldNames[schemaType];
	}

	static int getRandomKeyLength(int maxLength) {
		return random.nextInt(maxLength) + 1;
	}

	/**
	 * Create a new long-keyed record.
	 * @param table table
	 * @param randomKey use a random key if true, else use the next avaiable key
	 * @param varDataSize number of bytes created for all variable length fields
	 * @param doInsert insert record into table if true
	 * @return Record new record
	 */
	static Record createLongKeyRecord(Table table, boolean randomKey, int varDataSize,
			boolean doInsert) throws IOException, DuplicateKeyException {
		long key;
		if (randomKey) {
			key = random.nextLong();
		}
		else {
			key = table.getMaxKey() + 1;
		}
		try {
			Record rec = createRecord(table, key, varDataSize, doInsert);
			if (!randomKey) {
				Assert.assertEquals(rec.getKey(), table.getMaxKey());
			}
			return rec;
		}
		catch (DuplicateKeyException dke) {
			if (randomKey) {
				return createLongKeyRecord(table, randomKey, varDataSize, doInsert);
			}
			throw dke;
		}
	}

	/**
	 * Create a new random-BinaryField-keyed record.
	 * @param table
	 * @param maxKeyLength maximum key length; if < 0 keyLength = -maxKeyLength
	 * @param varDataSize
	 * @param doInsert
	 * @return Record
	 * @throws IOException
	 * @throws DuplicateKeyException
	 */
	static Record createBinaryKeyRecord(Table table, int maxKeyLength, int varDataSize,
			boolean doInsert) throws IOException, DuplicateKeyException {
		int keyLength =
			(maxKeyLength < 0) ? -maxKeyLength : DBTestUtils.getRandomKeyLength(maxKeyLength);
		byte[] bytes = new byte[keyLength];
		random.nextBytes(bytes);
		Field key = varKeyType.newField();
		key.setBinaryData(bytes);

		try {
			Record rec = createRecord(table, key, varDataSize, doInsert);
			Assert.assertEquals(key, rec.getKeyField());
			return rec;
		}
		catch (DuplicateKeyException dke) {
			return createBinaryKeyRecord(table, maxKeyLength, varDataSize, doInsert);
		}
	}

	/**
	 * Create a new record.
	 * @param table table
	 * @param key record key
	 *  @param varDataSize number of bytes created for all variable length fields
	 * @param doInsert insert record into table if true
	 * @return Record new record
	 * @throws IOException
	 * @throws DuplicateKeyException record with assigned key already exists in table.
	 */
	static Record createRecord(Table table, long key, int varDataSize, boolean doInsert)
			throws IOException, DuplicateKeyException {
		// Check for duplicate key
		if (doInsert) {
			Record oldRec = table.getRecord(key);
			if (oldRec != null) {
				throw new DuplicateKeyException();
			}
		}

		// Create record and fill with data
		Record rec = table.getSchema().createRecord(key);
		fillRecord(rec, varDataSize);

		// Insert record if requested
		if (doInsert) {
			int cnt = table.getRecordCount();
			table.putRecord(rec);
			Assert.assertEquals(1, table.getRecordCount() - cnt);
		}

		return rec;
	}

	/**
	 * Create a new record.  Only use with Long Key tables.
	 * @param table table
	 * @param key record key
	 *  @param varDataSize number of bytes created for all variable length fields
	 * @param doInsert insert record into table if true
	 * @return Record new record
	 * @throws IOException
	 * @throws DuplicateKeyException record with assigned key already exists in table.
	 */
	static Record createRecord(Table table, Field key, int varDataSize, boolean doInsert)
			throws IOException, DuplicateKeyException {
		// Check for duplicate key
		if (doInsert) {
			Record oldRec = table.getRecord(key);
			if (oldRec != null) {
				throw new DuplicateKeyException();
			}
		}

		// Create record and fill with data
		Record rec = table.getSchema().createRecord(key);
		fillRecord(rec, varDataSize);

		// Insert record if requested
		if (doInsert) {
			int cnt = table.getRecordCount();
			table.putRecord(rec);
			Assert.assertEquals(1, table.getRecordCount() - cnt);
		}

		return rec;
	}

	/**
	 * Create a new record whose value is in the center portion of the valid
	 * values range for byte, short, int, or long.
	 * @param table table
	 * @param key record key
	 *  @param varDataSize number of bytes created for all variable length fields
	 * @param doInsert insert record into table if true
	 * @return Record new record
	 * @throws IOException
	 * @throws DuplicateKeyException record with assigned key already exists in table.
	 */
	static Record createMidRangeRecord(Table table, long key, int varDataSize, boolean doInsert)
			throws IOException, DuplicateKeyException {
		// Check for duplicate key
		if (doInsert) {
			Record oldRec = table.getRecord(key);
			if (oldRec != null) {
				throw new DuplicateKeyException();
			}
		}

		// Create record and fill with data
		Record rec = table.getSchema().createRecord(key);
		fillMidRangeRecord(rec, varDataSize);

		// Insert record if requested
		if (doInsert) {
			int cnt = table.getRecordCount();
			table.putRecord(rec);
			Assert.assertEquals(1, table.getRecordCount() - cnt);
		}

		return rec;
	}

	/**
	 * Create a new record whose value is in the center portion of the valid
	 * values range for byte, short, int, or long.  Only use with Long Key tables.
	 * @param table table
	 * @param key record key
	 *  @param varDataSize number of bytes created for all variable length fields
	 * @param doInsert insert record into table if true
	 * @return Record new record
	 * @throws IOException
	 * @throws DuplicateKeyException record with assigned key already exists in table.
	 */
	static Record createMidRangeRecord(Table table, Field key, int varDataSize, boolean doInsert)
			throws IOException, DuplicateKeyException {
		// Check for duplicate key
		if (doInsert) {
			Record oldRec = table.getRecord(key);
			if (oldRec != null) {
				throw new DuplicateKeyException();
			}
		}

		// Create record and fill with data
		Record rec = table.getSchema().createRecord(key);
		fillMidRangeRecord(rec, varDataSize);

		// Insert record if requested
		if (doInsert) {
			int cnt = table.getRecordCount();
			table.putRecord(rec);
			Assert.assertEquals(1, table.getRecordCount() - cnt);
		}

		return rec;
	}

	/**
	 * Fill record with random data.
	 * @param rec record
	 * @param varDataSize number of bytes to fill into all variable length fields.
	 * NOTE: The StringField does not strictly follow the varDataSize paramter.
	 * A value less than 0 results in a null assignment to those fields.
	 */
	static void fillRecord(Record rec, int varDataSize) {

		Field[] fields = rec.getFields();
		for (int i = 0; i < fields.length; i++) {
			if (fields[i] instanceof ByteField) {
				rec.setByteValue(i, (byte) random.nextInt());
			}
			else if (fields[i] instanceof ShortField) {
				rec.setShortValue(i, (short) random.nextInt());
			}
			else if (fields[i] instanceof IntField) {
				rec.setIntValue(i, random.nextInt());
			}
			else if (fields[i] instanceof LongField) {
				rec.setLongValue(i, random.nextLong());
			}
			else if (fields[i] instanceof StringField) {
				int size = varDataSize;
				if (size < 0) {
					size = random.nextInt(6) - 1;
				}
				if (size < 0) {
					rec.setString(i, null);
				}
				else {
					char[] chars = new char[size];
					for (int n = 0; n < chars.length; n++) {
						chars[n] = (char) (random.nextInt() & 0x7fff);
					}
					String str = new String(chars);
					rec.setString(i, str);
				}
			}
			else if (fields[i] instanceof BinaryField) {
				int size = varDataSize;
				if (size < 0) {
					size = random.nextInt(6) - 1;
				}
				if (size < 0) {
					rec.setBinaryData(i, null);
				}
				else {
					byte[] bytes = new byte[size];
					random.nextBytes(bytes);
					rec.setBinaryData(i, bytes);
				}
			}
			else {
				Assert.fail();
			}
		}

	}

	/**
	 * Fill record with random data that falls int the middle range for
	 * the value type. The middle range is considered form half the min value
	 * to half the max value. It only applies to byte, short, int, and long currently.
	 * @param rec record
	 * @param varDataSize number of bytes to fill into all variable length fields.
	 * A value less than 0 results in a null assignment to those fields.
	 */
	static void fillMidRangeRecord(Record rec, int varDataSize) {

		Field[] fields = rec.getFields();
		for (int i = 0; i < fields.length; i++) {
			if (fields[i] instanceof ByteField) {
				rec.setByteValue(i,
					getRandomByte((byte) (Byte.MIN_VALUE / 2), (byte) (Byte.MAX_VALUE / 2)));
			}
			else if (fields[i] instanceof ShortField) {
				rec.setShortValue(i,
					getRandomShort((short) (Short.MIN_VALUE / 2), (short) (Short.MAX_VALUE / 2)));
			}
			else if (fields[i] instanceof IntField) {
				rec.setIntValue(i, getRandomInt((Integer.MIN_VALUE / 2), (Integer.MAX_VALUE / 2)));
			}
			else if (fields[i] instanceof LongField) {
				rec.setLongValue(i, getRandomLong((Long.MIN_VALUE / 2), (Long.MAX_VALUE / 2)));
			}
			else if (fields[i] instanceof StringField) {
				if (varDataSize < 0) {
					rec.setString(i, null);
				}
				else {
					char[] chars = new char[varDataSize / 2];
					for (int n = 0; n < chars.length; n++) {
						chars[n] =
							(char) (getRandomInt((Integer.MIN_VALUE / 2), (Integer.MAX_VALUE / 2)) &
								0x7fff);
					}
					String str = new String(chars);
					rec.setString(i, str);
				}
			}
			else if (fields[i] instanceof BinaryField) {
				if (varDataSize < 0) {
					rec.setBinaryData(i, null);
				}
				else {
					byte[] bytes = new byte[varDataSize];
					random.nextBytes(bytes);
					rec.setBinaryData(i, bytes);
				}
			}
			else {
				Assert.fail();
			}
		}

	}

	static byte getRandomByte(byte min, byte max) {
		byte value = 0;
		do {
			value = (byte) random.nextInt();
		}
		while ((value < min) || (value > max));
		return value;
	}

	static short getRandomShort(short min, short max) {
		short value = 0;
		do {
			value = (short) random.nextInt();
		}
		while ((value < min) || (value > max));
		return value;
	}

	static int getRandomInt(int min, int max) {
		int value = 0;
		do {
			value = random.nextInt();
		}
		while ((value < min) || (value > max));
		return value;
	}

	static long getRandomLong(long min, long max) {
		long value = 0;
		do {
			value = random.nextLong();
		}
		while ((value < min) || (value > max));
		return value;
	}

	static BinaryField increment(BinaryField field, int maxLength) {

		byte[] bytes = field.getBinaryData();
		if (bytes == null) {
			return new BinaryField(new byte[0]);
		}

		int len = bytes.length;
		byte[] newBytes;
		if (len < maxLength) {
			// Simply increase length by adding trailing 0 byte
			newBytes = new byte[len + 1];
			System.arraycopy(bytes, 0, newBytes, 0, len);
			newBytes[len] = (byte) 0x00;
		}
		else if (bytes[len - 1] == (byte) 0xff) {
			// chop trailing ff bytes, increment new last byte
			int newLen = len;
			while (newLen > 0 && bytes[newLen - 1] == (byte) 0xff) {
				--newLen;
			}
			newBytes = new byte[newLen];
			System.arraycopy(bytes, 0, newBytes, 0, newLen);
			if (newLen > 0) {
				++newBytes[newLen - 1];
			}
			else {
				// wrap error
				Assert.fail("Bad test data: attempt to increment max value");
			}
		}
		else {
			// increment last byte only
			newBytes = new byte[len];
			System.arraycopy(bytes, 0, newBytes, 0, len);
			++newBytes[len - 1];
		}
		return new BinaryField(newBytes);
	}

	static BinaryField decrement(BinaryField field, int maxLength) {

		byte[] bytes = field.getBinaryData();
		if (bytes == null) {
			Assert.fail("Bad test data: attempt to deccrement min value ");
		}

		int len = bytes.length;
		if (len == 0) {
			return new BinaryField(null);
		}
		byte[] newBytes;
		if (bytes[len - 1] == 0) {
			// chop trailing 00 byte
			newBytes = new byte[len - 1];
			System.arraycopy(bytes, 0, newBytes, 0, len - 1);
		}
		else if (len < maxLength) {
			// Simply create maximum length value with trailing ff's
			newBytes = new byte[maxLength];
			System.arraycopy(bytes, 0, newBytes, 0, len);
			--newBytes[len - 1];
			for (int i = len; i < maxLength; i++) {
				newBytes[i] = (byte) 0xff;
			}
		}
		else {
			// decrement last byte only
			newBytes = new byte[len];
			System.arraycopy(bytes, 0, newBytes, 0, len);
			--newBytes[len - 1];
		}
		return new BinaryField(newBytes);
	}

	static BinaryField getMaxValue(int maxLength) {
		byte[] bytes = new byte[maxLength];
		for (int i = 0; i < maxLength; i++) {
			bytes[i] = (byte) 0xff;
		}
		return new BinaryField(bytes);
	}

	public static void main(String[] args) {

		int maxLen = 3;

		System.out.println("Incrementing...");
		BinaryField bf = new BinaryField(null);
		BinaryField lastBf = bf;
		int cnt = 0;
		try {
			while (true) {
				bf = increment(bf, maxLen);
//				System.out.println(bf.toString());
				if (bf.compareTo(lastBf) <= 0) {
					System.out.println("Failed: " + bf + " is not greater than " + lastBf);
					System.exit(-1);
				}
				lastBf = bf;
				++cnt;
			}
		}
		catch (Exception e) {
//			e.printStackTrace();
		}
		System.out.println("Incremented " + cnt + " values");

		System.out.println("Decrementing...");
		cnt = 0;
		try {
			while (true) {
				bf = decrement(bf, maxLen);
//				System.out.println(bf.toString());
				if (bf.compareTo(lastBf) >= 0) {
					System.out.println("Failed: " + bf + " is not less than " + lastBf);
					System.exit(-1);
				}
				lastBf = bf;
				++cnt;
			}
		}
		catch (Exception e) {
//			e.printStackTrace();
		}
		System.out.println("Decremented " + cnt + " values");
	}

	static BufferFileManager getBufferFileManager(File dir, String dbName) {
		return new DummyBufferFileMgr(dir, dbName, false, false);
	}
}

class DuplicateKeyException extends Exception {

	DuplicateKeyException() {
		super();
	}

}
