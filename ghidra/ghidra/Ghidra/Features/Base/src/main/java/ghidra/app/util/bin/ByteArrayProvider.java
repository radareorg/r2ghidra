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
package ghidra.app.util.bin;

import java.io.*;

/**
 * An implementation of {@link ByteProvider} where the underlying bytes are supplied by a static 
 * byte array.
 * <p>
 * NOTE: Use of this class is discouraged when the byte array could be large.
 */
public class ByteArrayProvider implements ByteProvider {
	private byte[] srcBytes;
	private String name;

	/**
	 * Constructs a {@link ByteArrayProvider} using the specified byte array
	 * 
	 * @param bytes the underlying byte array
	 */
	public ByteArrayProvider(byte[] bytes) {
		this.srcBytes = bytes;
	}

	/**
	 * Constructs a {@link ByteArrayProvider} using the specified byte array
	 * 
	 * @param name the name of the {@link ByteProvider} 
	 * @param bytes the underlying byte array
	 */
	public ByteArrayProvider(String name, byte[] bytes) {
		this.name = name;
		this.srcBytes = bytes;
	}

	@Override
	public void close() {
		// don't do anything for now
	}

	@Override
	public File getFile() {
		return null;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getAbsolutePath() {
		return "";
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		assertValidIndex(index, true);
		return new ByteArrayInputStream(srcBytes, (int) index, srcBytes.length - (int) index);
	}

	@Override
	public long length() {
		return srcBytes.length;
	}

	@Override
	public boolean isValidIndex(long index) {
		return index >= 0 && index < length();
	}

	/**
	 * Throws {@link IOException} if index is not a valid position in the buffer
	 *
	 * @param index position in buffer to test
	 * @param inclusiveMax allow buffer.length as index
	 * @throws IOException if index is out of bounds
	 */
	private void assertValidIndex(long index, boolean inclusiveMax) throws IOException {
		if (index < 0 || index > srcBytes.length ||
			(inclusiveMax == false && index == srcBytes.length)) {
			throw new IOException(
				"Invalid position, index: " + index + ", max is: " + srcBytes.length);
		}
	}

	@Override
	public byte readByte(long index) throws IOException {
		assertValidIndex(index, false);
		return srcBytes[(int) index];
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		assertValidIndex(index, true);
		if (index + length > srcBytes.length) {
			throw new IOException("Attempt to read beyond end of byte data");
		}
		byte[] destBytes = new byte[(int) length];
		System.arraycopy(srcBytes, (int) index, destBytes, 0, (int) length);
		return destBytes;
	}
}
