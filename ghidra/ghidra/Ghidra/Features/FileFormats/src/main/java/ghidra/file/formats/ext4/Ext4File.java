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
package ghidra.file.formats.ext4;

public class Ext4File {

	private String name;
	private Ext4Inode inode;
	
	public Ext4File(String name, Ext4Inode inode) {
		this.name = name;
		this.inode = inode;
	}
	
	public Ext4File(String name) {
		this.name = name;
	}
	
	public Ext4File(Ext4Inode inode) {
		this.inode = inode;
	}
	
	public Ext4File() {
		
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Ext4Inode getInode() {
		return inode;
	}

	public void setInode(Ext4Inode inode) {
		this.inode = inode;
	}
	
}
