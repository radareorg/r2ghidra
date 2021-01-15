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
package ghidra.formats.gfilesystem.factory;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;

/**
 * A {@link GFileSystemProbe} interface for filesystems that need all available
 * references to the source file, including a {@link ByteProvider}.
 */
public interface GFileSystemProbeFull extends GFileSystemProbe {
	/**
	 * Probes the specified {@code containerFile} to determine if this filesystem implementation
	 * can handle the file.
	 * 
	 * @param containerFSRL the {@link FSRL} of the file being probed
	 * @param byteProvider a {@link ByteProvider} containing the contents of the file being probed. 
	 * Implementors of this method should <b>NOT</b> {@link ByteProvider#close() close()} this
	 * object.  
	 * @param containerFile the {@link File} (probably in the filecache with non-useful filename)
	 * being probed.
	 * @param fsService a reference to the {@link FileSystemService} object
	 * @param monitor a {@link TaskMonitor} that should be polled to see if the user has
	 * requested to cancel the operation, and updated with progress information. 
	 * @return {@code true} if the specified file is handled by this filesystem implementation, 
	 * {@code false} if not.
	 * @throws IOException if there is an error reading files.
	 * @throws CancelledException if the user cancels
	 */
	public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
			FileSystemService fsService, TaskMonitor monitor)
					throws IOException, CancelledException;
}
