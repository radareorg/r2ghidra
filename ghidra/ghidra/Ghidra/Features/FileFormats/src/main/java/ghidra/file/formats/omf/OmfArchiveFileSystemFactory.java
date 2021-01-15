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
package ghidra.file.formats.omf;

import java.io.File;
import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.omf.OmfFileHeader;
import ghidra.app.util.bin.format.omf.OmfLibraryRecord;
import ghidra.app.util.opinion.OmfLoader;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class OmfArchiveFileSystemFactory
		implements GFileSystemFactoryFull<OmfArchiveFileSystem>, GFileSystemProbeFull {

	@Override
	public OmfArchiveFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL,
			ByteProvider byteProvider, File containerFile, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {

		OmfArchiveFileSystem fs = new OmfArchiveFileSystem(targetFSRL, byteProvider);
		fs.mount(monitor);
		return fs;
	}

	@Override
	public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (byteProvider.length() < OmfLoader.MIN_BYTE_LENGTH) {
			return false;
		}

		try {
			BinaryReader reader = OmfFileHeader.createReader(byteProvider);
			return OmfLibraryRecord.checkMagicNumer(reader);
		}
		catch (IOException e) {
			return false;
		}
	}
}
