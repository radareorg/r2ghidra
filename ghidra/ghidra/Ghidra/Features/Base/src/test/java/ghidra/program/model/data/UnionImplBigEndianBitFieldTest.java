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
package ghidra.program.model.data;

import org.junit.Test;

public class UnionImplBigEndianBitFieldTest extends AbstractCompositeImplBitFieldTest {

	// NOTE: verified bitfields sample built with mips-elf-gcc (GCC) 4.9.2

	private static DataTypeManager dataMgr;

	@Override
	protected DataTypeManager getDataTypeManager() {
		synchronized (StructureImplBigEndianBitFieldTest.class) {
			if (dataMgr == null) {
				DataOrganizationImpl dataOrg = DataOrganizationImpl.getDefaultOrganization(null);
				DataOrganizationTestUtils.initDataOrganization32BitMips(dataOrg);
				dataMgr = new MyDataTypeManager("test", dataOrg);
			}
			return dataMgr;
		}
	}

	@Test
	public void testUnionBitFieldsU1() {
		Union struct = getUnion("U1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/U1\n" + 
			"Aligned\n" + 
			"Union U1 {\n" + 
			"   0   int:4(4)   1   a   \"\"\n" + 
			"   0   int:2(6)   1   b   \"\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testUnionBitFieldsU1z() {
		Union struct = getUnion("U1z");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/U1z\n" + 
				"Aligned\n" + 
				"Union U1z {\n" + 
				"   0   int:4(4)   1   a   \"\"\n" + 
				"   0   longlong:0(7)   1      \"\"\n" + // has no impact
				"   0   int:2(6)   1   b   \"\"\n" + 
				"}\n" + 
				"Size = 4   Actual Alignment = 4", struct);
		//@formatter:on
	}

	@Test
	public void testUnionBitFieldsU1p1() {
		Union struct = getUnion("U1p1");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/U1p1\n" + 
			"Aligned pack(1)\n" + 
			"Union U1p1 {\n" + 
			"   0   int:4(4)   1   a   \"\"\n" + 
			"   0   int:2(6)   1   b   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testUnionBitFieldsU1p1z() {
		Union struct = getUnion("U1p1z");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/U1p1z\n" + 
			"Aligned pack(1)\n" + 
			"Union U1p1z {\n" + 
			"   0   int:4(4)   1   a   \"\"\n" + 
			"   0   longlong:0(7)   1      \"\"\n" + // has no impact
			"   0   int:2(6)   1   b   \"\"\n" + 
			"}\n" + 
			"Size = 1   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testUnionBitFieldsU1p2() {
		Union struct = getUnion("U1p2");
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/U1p2\n" + 
			"Aligned pack(2)\n" + 
			"Union U1p2 {\n" + 
			"   0   int:4(4)   1   a   \"\"\n" + 
			"   0   int:2(6)   1   b   \"\"\n" + 
			"}\n" + 
			"Size = 2   Actual Alignment = 2", struct);
		//@formatter:on
	}
}
