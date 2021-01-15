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
package mdemangler.datatype.extended;

import mdemangler.MDMang;

/**
 * This class represents an int64 data type within a Microsoft mangled symbol.
 */
public class MDInt64DataType extends MDExtendedType {

	public MDInt64DataType(MDMang dmang) {
		super(dmang);
	}

	@Override
	public String getTypeName() {
		return "__int64";
	}
}
