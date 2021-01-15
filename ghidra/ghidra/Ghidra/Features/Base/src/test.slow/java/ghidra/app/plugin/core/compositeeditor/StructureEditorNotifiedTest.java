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
package ghidra.app.plugin.core.compositeeditor;

import static org.junit.Assert.*;

import java.awt.Window;

import javax.swing.SwingUtilities;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitorAdapter;

public class StructureEditorNotifiedTest extends AbstractStructureEditorTest {

	protected void init(Structure dt, final Category cat) {
		boolean commit = true;
		startTransaction("Structure Editor Test Initialization");
		try {
			DataTypeManager dataTypeManager = cat.getDataTypeManager();
			if (dt.getDataTypeManager() != dataTypeManager) {
				dt = (Structure) dt.clone(dataTypeManager);
			}
			CategoryPath categoryPath = cat.getCategoryPath();
			if (!dt.getCategoryPath().equals(categoryPath)) {
				try {
					dt.setCategoryPath(categoryPath);
				}
				catch (DuplicateNameException e) {
					commit = false;
					Assert.fail(e.getMessage());
				}
			}
		}
		finally {
			endTransaction(commit);
		}

		Structure structDt = dt;
		runSwing(() -> {
			installProvider(new StructureEditorProvider(plugin, structDt, false));
		});

		model = provider.getModel();
		startTransaction("Modify Program");
	}

	@Override
	protected void cleanup() {
		endTransaction(false);
		provider.dispose();
	}

	@Test
	public void testCategoryAdded() {
		// Nothing to test here.
	}

	@Test
	public void testComponentDtCategoryMoved() throws Exception {
		init(complexStructure, pgmTestCat);

		assertEquals("simpleStructure", getDataType(21).getName());
		assertEquals("/aa/bb", getDataType(21).getCategoryPath().getPath());
		pgmTestCat.moveCategory(pgmBbCat, TaskMonitorAdapter.DUMMY_MONITOR);
		waitForPostedSwingRunnables();
		assertEquals("/testCat/bb", getDataType(21).getCategoryPath().getPath());
	}

	@Test
	public void testEditedDtCategoryMoved() throws Exception {
		init(simpleStructure, pgmBbCat);

		assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		pgmTestCat.moveCategory(pgmBbCat, TaskMonitorAdapter.DUMMY_MONITOR);
		waitForPostedSwingRunnables();
		assertTrue(
			model.getOriginalCategoryPath().getPath().startsWith(pgmTestCat.getCategoryPathName()));
		assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
	}

	@Test
	public void testComponentDtCategoryRemoved() {
		// Nothing to test here.
	}

	@Test
	public void testEditedDataTypeRemoved() throws Exception {
		Category tempCat;
		try {
			startTransaction("Modify Program");
			tempCat = pgmRootCat.createCategory("Temp");
			tempCat.moveDataType(complexStructure, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		finally {
			endTransaction(true);
		}
		init(complexStructure, tempCat);
		int num = model.getNumComponents();
		int len = model.getLength();
		DataType dataType10 = model.viewComposite.getComponent(10).getDataType();
		assertEquals("complexStructure *", dataType10.getDisplayName());
		assertEquals(4, dataType10.getLength());

		SwingUtilities.invokeLater(() -> {
			programDTM.remove(complexStructure, TaskMonitorAdapter.DUMMY_MONITOR);
			programDTM.getCategory(pgmRootCat.getCategoryPath()).removeCategory("Temp",
				TaskMonitorAdapter.DUMMY_MONITOR);
		});
		waitForPostedSwingRunnables();
		// complexStructure* gets removed and becomes 4 undefined bytes in this editor.
		assertEquals(num + 3, model.getNumComponents());
		assertEquals(len, model.getLength());
		dataType10 = model.viewComposite.getComponent(10).getDataType();
		assertEquals("undefined", dataType10.getDisplayName());
		assertEquals(1, dataType10.getLength());
	}

	@Test
	public void testComponentDtCategoryRenamed() throws Exception {
		init(complexStructure, pgmTestCat);

		assertEquals("/aa/bb", getDataType(21).getCategoryPath().getPath());
		pgmBbCat.setName("NewBB2");// Was /aa/bb
		waitForPostedSwingRunnables();
		assertEquals("/aa/NewBB2", getDataType(21).getCategoryPath().getPath());
	}

	@Test
	public void testEditedDtCategoryRenamed() throws Exception {
		init(simpleStructure, pgmBbCat);

		assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		pgmBbCat.setName("NewBB2");// Was /aa/bb
		waitForPostedSwingRunnables();
		assertEquals("/aa/NewBB2", model.getOriginalCategoryPath().getPath());
	}

	@Test
	public void testDataTypeAdded() {
		// FUTURE (low priority)
		// Try to add an archive data type to the editor, then add
		// the same named data type to the original data type manager.
	}

	@Test
	public void testComponentDataTypeChangedLocked() {
		init(complexStructure, pgmTestCat);

//		model.setLocked(true);
//		assertTrue(model.isLocked());
		int len = model.getLength();
		int num = model.getNumComponents();
		// Clone the data types we want to hold onto for comparison later, since reload can close the viewDTM.
		DataType dt16 = getDataType(16).clone(programDTM);// struct array
		DataType dt19 = getDataType(19).clone(programDTM);// struct typedef
		DataType dt21 = getDataType(21).clone(programDTM);// struct
		int len16 = dt16.getLength();
		int len19 = dt19.getLength();
		int len21 = dt21.getLength();
		// Change the struct.  simpleStructure was 29 bytes.
		SwingUtilities.invokeLater(() -> simpleStructure.add(new DWordDataType()));
		waitForPostedSwingRunnables();
		// Check that the viewer now has the modified struct.
		// Components 16, 19, & 21 all change size.
		int newLen16 = len16 + (3 * 4);
		int newLen19 = len19 + 4;
		int newLen21 = len21 + 4;
		assertEquals(newLen16, getDataType(16).getLength());
		assertEquals(newLen19, getDataType(19).getLength());
		assertEquals(newLen21, getDataType(21).getLength());
		assertEquals(len16, model.getComponent(16).getLength());
		assertEquals(len19, model.getComponent(19).getLength());
		assertEquals(len21, model.getComponent(21).getLength());
		assertEquals(len, model.getLength());
		assertEquals(num, model.getNumComponents());
		assertTrue(getMnemonic(16).startsWith("TooBig:"));
		assertTrue(getMnemonic(19).startsWith("TooBig:"));
		assertTrue(getMnemonic(21).startsWith("TooBig:"));
	}

	@Test
	public void testComponentDataTypeChangedUnlocked() {
		init(complexStructure, pgmTestCat);

//		model.setLocked(false);
//		assertTrue(!model.isLocked());
		int len = model.getLength();
		int num = model.getNumComponents();
		// Clone the data types we want to hold onto for comparison later, since reload can close the viewDTM.
		DataType dt16 = getDataType(16).clone(programDTM);// struct array
		DataType dt19 = getDataType(19).clone(programDTM);// struct typedef
		DataType dt21 = getDataType(21).clone(programDTM);// struct
		int len16 = dt16.getLength();
		int len19 = dt19.getLength();
		int len21 = dt21.getLength();
		// Change the struct.  simpleStructure was 29 bytes.
		SwingUtilities.invokeLater(() -> simpleStructure.add(new DWordDataType()));
		waitForPostedSwingRunnables();
		// Check that the viewer now has the modified struct.
		// Components 16, 19, & 21 all change size.
		int newLen16 = len16 + (3 * 4);
		int newLen19 = len19 + 4;
		int newLen21 = len21 + 4;
		assertEquals(newLen16, getDataType(16).getLength());
		assertEquals(newLen19, getDataType(19).getLength());
		assertEquals(newLen21, getDataType(21).getLength());
		assertEquals(len16, model.getComponent(16).getLength());
		assertEquals(len19, model.getComponent(19).getLength());
		assertEquals(len21, model.getComponent(21).getLength());
		assertEquals(len, model.getLength());
		assertEquals(num, model.getNumComponents());
		assertTrue(getMnemonic(16).startsWith("TooBig:"));
		assertTrue(getMnemonic(19).startsWith("TooBig:"));
		assertTrue(getMnemonic(21).startsWith("TooBig:"));
	}

	@Test
	public void testComponentDataTypeChangedBiggerConsumeSome() {
		try {
			final DataType dword = new DWordDataType();
			final DataType ascii = new CharDataType();
			final DataType undef = DataType.DEFAULT;
			startTransaction("Modify Program");

			// Change the struct.  simpleStructure was 29 bytes.
			SwingUtilities.invokeLater(() -> {
				emptyStructure.add(dword);
				emptyStructure.add(simpleStructure);
				emptyStructure.growStructure(6);
				emptyStructure.add(ascii);
			});
			waitForPostedSwingRunnables();
			emptyStructure = (Structure) programDTM.resolve(emptyStructure, null);
			try {
				emptyStructure.setCategoryPath(pgmTestCat.getCategoryPath());
			}
			catch (DuplicateNameException e) {
				Assert.fail(e.getMessage());
			}

			runSwing(() -> {
				installProvider(new StructureEditorProvider(plugin, emptyStructure, false));
				model = provider.getModel();
//					model.setLocked(true);
			});
//			assertTrue(model.isLocked());
			int len = model.getLength();
			int num = model.getNumComponents();

			int origLen = simpleStructure.getLength();
			// Change the struct.  simpleStructure was 29 bytes.
			SwingUtilities.invokeLater(() -> simpleStructure.add(new DWordDataType()));
			waitForPostedSwingRunnables();
			int newLen = origLen + 4;

			assertEquals(len, model.getLength());
			assertEquals(num - 4, model.getNumComponents());
			assertTrue(dword.isEquivalent(getDataType(0)));
			assertTrue(simpleStructure.isEquivalent(getDataType(1)));
			assertEquals(newLen, getDataType(1).getLength());
			assertTrue(undef.isEquivalent(getDataType(3)));
			assertTrue(ascii.isEquivalent(getDataType(4)));
			assertEquals(4, model.getComponent(0).getLength());
			assertEquals(newLen, model.getComponent(1).getLength());
			assertEquals(1, model.getComponent(2).getLength());
			assertEquals(1, model.getComponent(3).getLength());
			assertEquals(1, model.getComponent(4).getLength());
			assertTrue(!getMnemonic(1).startsWith("TooBig:"));
		}
		finally {
			endTransaction(false);
		}
	}

	@Test
	public void testComponentDataTypeChangedBiggerConsumeAll() {
		try {
			final DataType dword = new DWordDataType();
			final DataType ascii = new CharDataType();
			startTransaction("Modify Program");

			// Change the struct.  simpleStructure was 29 bytes.
			SwingUtilities.invokeLater(() -> {
				emptyStructure.add(dword);
				emptyStructure.add(simpleStructure);
				emptyStructure.growStructure(4);
				emptyStructure.add(ascii);
			});
			waitForPostedSwingRunnables();
			emptyStructure = (Structure) programDTM.resolve(emptyStructure, null);
			try {
				emptyStructure.setCategoryPath(pgmTestCat.getCategoryPath());
			}
			catch (DuplicateNameException e) {
				Assert.fail(e.getMessage());
			}

			runSwing(() -> {
				installProvider(new StructureEditorProvider(plugin, emptyStructure, false));
				model = provider.getModel();
//					model.setLocked(true);
			});
//			assertTrue(model.isLocked());
			int len = model.getLength();
			int num = model.getNumComponents();

			int origLen = simpleStructure.getLength();
			// Change the struct.  simpleStructure was 29 bytes.
			SwingUtilities.invokeLater(() -> simpleStructure.add(new DWordDataType()));
			waitForPostedSwingRunnables();
			int newLen = origLen + 4;

			assertEquals(len, model.getLength());
			assertEquals(num - 4, model.getNumComponents());
			assertTrue(dword.isEquivalent(getDataType(0)));
			assertTrue(simpleStructure.isEquivalent(getDataType(1)));
			assertEquals(newLen, getDataType(1).getLength());
			assertTrue(ascii.isEquivalent(getDataType(2)));
			assertEquals(4, model.getComponent(0).getLength());
			assertEquals(newLen, model.getComponent(1).getLength());
			assertEquals(1, model.getComponent(2).getLength());
			assertTrue(!getMnemonic(1).startsWith("TooBig:"));
		}
		finally {
			endTransaction(false);
		}
	}

	@Test
	public void testComponentDataTypeChangedBiggerNotEnough() {
		try {
			final DataType dword = new DWordDataType();
			final DataType ascii = new CharDataType();
			startTransaction("Modify Program");

			// Change the struct.  simpleStructure was 29 bytes.
			SwingUtilities.invokeLater(() -> {
				emptyStructure.add(dword);
				emptyStructure.add(simpleStructure);
				emptyStructure.growStructure(2);
				emptyStructure.add(ascii);
			});
			waitForPostedSwingRunnables();
			emptyStructure = (Structure) programDTM.resolve(emptyStructure, null);
			try {
				emptyStructure.setCategoryPath(pgmTestCat.getCategoryPath());
			}
			catch (DuplicateNameException e) {
				Assert.fail(e.getMessage());
			}
			runSwing(() -> {
				installProvider(new StructureEditorProvider(plugin, emptyStructure, false));
				model = provider.getModel();
//					model.setLocked(true);
			});
//			assertTrue(model.isLocked());
			int len = model.getLength();
			int num = model.getNumComponents();

			int origLen = simpleStructure.getLength();
			// Change the struct.  simpleStructure was 29 bytes.
			SwingUtilities.invokeLater(() -> simpleStructure.add(new DWordDataType()));
			waitForPostedSwingRunnables();
			int newDtLen = origLen + 4;
			int newCompLen = origLen + 2;

			assertEquals(len, model.getLength());
			assertEquals(num - 2, model.getNumComponents());
			assertTrue(dword.isEquivalent(getDataType(0)));
			assertTrue(simpleStructure.isEquivalent(getDataType(1)));
			assertEquals(newDtLen, getDataType(1).getLength());
			assertTrue(ascii.isEquivalent(getDataType(2)));
			assertEquals(4, model.getComponent(0).getLength());
			assertEquals(newCompLen, model.getComponent(1).getLength());
			assertEquals(1, model.getComponent(2).getLength());
			assertTrue(getMnemonic(1).startsWith("TooBig:"));
		}
		finally {
			endTransaction(false);
		}
	}

	@Test
	public void testComponentDataTypeChangedSmaller() {
		try {
			final DataType dword = new DWordDataType();
			final DataType ascii = new CharDataType();
			final DataType undef = DataType.DEFAULT;
			startTransaction("Modify Program");

			// Change the struct.  simpleStructure was 29 bytes.
			SwingUtilities.invokeLater(() -> {
				emptyStructure.add(dword);
				emptyStructure.add(simpleStructure);
				emptyStructure.add(ascii);
			});
			waitForPostedSwingRunnables();
			emptyStructure = (Structure) programDTM.resolve(emptyStructure, null);
			try {
				emptyStructure.setCategoryPath(pgmTestCat.getCategoryPath());
			}
			catch (DuplicateNameException e) {
				Assert.fail(e.getMessage());
			}
			runSwing(() -> {
				installProvider(new StructureEditorProvider(plugin, emptyStructure, false));
				model = provider.getModel();
//					model.setLocked(true);
			});
//			assertTrue(model.isLocked());
			int len = model.getLength();
			int num = model.getNumComponents();

			int origLen = simpleStructure.getLength();
			// Change the struct.  simpleStructure was 29 bytes.
			SwingUtilities.invokeLater(() -> simpleStructure.delete(2));
			waitForPostedSwingRunnables();
			int newLen = origLen - 2;

			assertEquals(len, model.getLength());
			assertEquals(num + 2, model.getNumComponents());
			assertTrue(dword.isEquivalent(getDataType(0)));
			assertTrue(simpleStructure.isEquivalent(getDataType(1)));
			assertEquals(newLen, getDataType(1).getLength());
			assertTrue(undef.isEquivalent(getDataType(2)));
			assertTrue(undef.isEquivalent(getDataType(3)));
			assertTrue(ascii.isEquivalent(getDataType(4)));
			assertEquals(4, model.getComponent(0).getLength());
			assertEquals(newLen, model.getComponent(1).getLength());
			assertEquals(1, model.getComponent(2).getLength());
			assertEquals(1, model.getComponent(3).getLength());
			assertEquals(1, model.getComponent(4).getLength());
			assertTrue(!getMnemonic(1).startsWith("TooBig:"));
		}
		finally {
			endTransaction(false);
		}
	}

	@Test
	public void testModifiedEditedDataTypeChangedYes() throws Exception {
		Window dialog;
		init(complexStructure, pgmTestCat);

		runSwing(() -> {
			try {
//					model.setLocked(false);
				model.insert(model.getNumComponents(), new ByteDataType(), 1);
				model.insert(model.getNumComponents(), new PointerDataType(), 4);
			}
			catch (UsrException e) {
				Assert.fail(e.getMessage());
			}
		});
		SwingUtilities.invokeLater(() -> complexStructure.add(new CharDataType()));
		waitForPostedSwingRunnables();
		DataType origCopy = complexStructure.clone(null);

		// Verify the Reload Structure Editor? dialog is displayed.
		dialog = env.waitForWindow("Reload Structure Editor?", 1000);
		assertNotNull(dialog);
		pressButtonByText(dialog, "Yes");
		dialog.dispose();
		dialog = null;

		assertEquals(((Structure) origCopy).getNumComponents(), model.getNumComponents());
		assertTrue(origCopy.isEquivalent(model.viewComposite));
	}

	@Test
	public void testModifiedEditedDataTypeChangedNo() throws Exception {
		Window dialog;
		init(complexStructure, pgmTestCat);

		runSwing(() -> {
			try {
//					model.setLocked(false);
				model.insert(model.getNumComponents(), new ByteDataType(), 1);
				model.insert(model.getNumComponents(), new PointerDataType(), 4);
			}
			catch (UsrException e) {
				Assert.fail(e.getMessage());
			}
		});
		DataType viewCopy = model.viewComposite.clone(null);
		SwingUtilities.invokeLater(() -> complexStructure.add(new CharDataType()));
		waitForPostedSwingRunnables();

		// Verify the Reload Structure Editor? dialog is displayed.
		dialog = env.waitForWindow("Reload Structure Editor?", 1000);
		assertNotNull(dialog);
		pressButtonByText(dialog, "No");
		dialog.dispose();
		dialog = null;

		assertEquals(((Structure) viewCopy).getNumComponents(), model.getNumComponents());
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
	}

	@Test
	public void testUnmodifiedEditedDataTypeChanged() {
		init(complexStructure, pgmTestCat);

		SwingUtilities.invokeLater(() -> complexStructure.add(new CharDataType()));
		waitForPostedSwingRunnables();
		assertTrue(complexStructure.isEquivalent(model.viewComposite));
	}

	@Test
	public void testComponentDataTypeMoved() {
		init(complexStructure, pgmTestCat);

		assertEquals(23, model.getNumComponents());
		assertTrue(simpleStructure.isEquivalent(getDataType(21)));
		assertEquals(simpleStructure.getCategoryPath().getPath(),
			pgmBbCat.getCategoryPath().getPath());
		SwingUtilities.invokeLater(() -> {
			try {
				pgmAaCat.moveDataType(simpleStructure, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
			catch (DataTypeDependencyException e) {
			}
		});
		waitForPostedSwingRunnables();
		assertEquals(23, model.getNumComponents());
		assertTrue(simpleStructure.isEquivalent(getDataType(21)));
		assertEquals(simpleStructure.getCategoryPath().getPath(),
			pgmAaCat.getCategoryPath().getPath());
	}

	@Test
	public void testEditedDataTypeMoved() {
		init(complexStructure, pgmTestCat);

		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		SwingUtilities.invokeLater(() -> {
			try {
				pgmAaCat.moveDataType(complexStructure, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
			catch (DataTypeDependencyException e) {
			}
		});
		waitForPostedSwingRunnables();
		assertEquals(pgmAaCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
	}

	@Test
	public void testComponentDataTypeRemoved() {
		init(complexStructure, pgmTestCat);
		DataType undef = DataType.DEFAULT;

		assertEquals(23, model.getNumComponents());
		// Clone the data types we want to hold onto for comparison later, since reload can close the viewDTM.
		DataType dt3 = getDataType(3).clone(programDTM);
		DataType dt5 = getDataType(5).clone(programDTM);
		DataType dt8 = getDataType(8).clone(programDTM);
		DataType dt10 = getDataType(10).clone(programDTM);

		SwingUtilities.invokeLater(() -> complexStructure.getDataTypeManager().remove(simpleUnion,
			TaskMonitorAdapter.DUMMY_MONITOR));
		waitForPostedSwingRunnables();

		assertEquals(30, model.getNumComponents());
		assertTrue(dt3.isEquivalent(getDataType(3)));
		assertTrue(undef.isEquivalent(getDataType(4)));
		assertTrue(undef.isEquivalent(getDataType(11)));
		assertTrue(dt5.isEquivalent(getDataType(12)));
		assertTrue(dt8.isEquivalent(getDataType(15)));
		assertTrue(undef.isEquivalent(getDataType(16)));
		assertTrue(dt10.isEquivalent(getDataType(17)));
		assertEquals(4, getOffset(3));
		assertEquals(16, getOffset(12));
		assertEquals(24, getOffset(15));
		assertEquals(33, getOffset(17));
	}

	@Test
	public void testOnlyComponentDataTypeRemoved() throws Exception {
		init(emptyStructure, pgmTestCat);

		SwingUtilities.invokeLater(() -> {
			try {
				model.add(simpleStructure);
			}
			catch (UsrException e) {
				Assert.fail();
			}
		});
		waitForPostedSwingRunnables();
		assertTrue(simpleStructure.isEquivalent(getDataType(0)));

		SwingUtilities.invokeLater(() -> simpleStructure.getDataTypeManager().remove(
			simpleStructure, TaskMonitorAdapter.DUMMY_MONITOR));
		waitForPostedSwingRunnables();
		assertEquals(29, model.getNumComponents());// becomes undefined bytes
	}

	@Test
	public void testComponentDataTypeRenamed() throws Exception {
		init(complexStructure, pgmTestCat);

		assertTrue(simpleStructure.isEquivalent(((Pointer) getDataType(6)).getDataType()));
		assertTrue(simpleStructure.isEquivalent(getDataType(21)));
		assertEquals("simpleStructure *", getDataType(6).getDisplayName());
		assertEquals("simpleStructure[3]", getDataType(16).getDisplayName());
		assertEquals("simpleStructure *[7]", getDataType(17).getDisplayName());
		assertEquals("simpleStructure", getDataType(21).getDisplayName());
		assertEquals(simpleStructure.getPathName(), getDataType(21).getPathName());
		SwingUtilities.invokeLater(() -> {
			try {
				simpleStructure.setName("NewSimpleStructure");
			}
			catch (UsrException e) {
				Assert.fail();
			}
		});
		waitForPostedSwingRunnables();
		assertEquals("NewSimpleStructure *", getDataType(6).getDisplayName());
		assertEquals("NewSimpleStructure[3]", getDataType(16).getDisplayName());
		assertEquals("NewSimpleStructure *[7]", getDataType(17).getDisplayName());
		assertEquals("NewSimpleStructure", getDataType(21).getDisplayName());
		assertEquals(simpleStructure.getPathName(), getDataType(21).getPathName());
	}

	@Test
	public void testOldNameEditedDataTypeRenamed() throws Exception {
		init(complexStructure, pgmTestCat);

		assertEquals(complexStructure.getDataTypePath(), model.getOriginalDataTypePath());
		assertEquals(complexStructure.getPathName(), model.viewComposite.getPathName());
		SwingUtilities.invokeLater(() -> {
			try {
				complexStructure.setName("NewComplexStructure");
			}
			catch (UsrException e) {
				Assert.fail();
			}
		});
		waitForPostedSwingRunnables();
		assertEquals(complexStructure.getDataTypePath(), model.getOriginalDataTypePath());
		assertEquals(complexStructure.getPathName(), model.viewComposite.getPathName());
		assertEquals("NewComplexStructure", model.getCompositeName());
	}

	@Test
	public void testNewNameEditedDataTypeRenamed() throws Exception {
		init(complexStructure, pgmTestCat);

		SwingUtilities.invokeLater(() -> {
			try {
				model.setName("EditedComplexStructure");
			}
			catch (UsrException e) {
				Assert.fail();
			}
		});
		waitForPostedSwingRunnables();
		assertEquals(complexStructure.getDataTypePath(), model.getOriginalDataTypePath());
		assertTrue(
			!complexStructure.getDataTypePath().equals(model.viewComposite.getDataTypePath()));

		SwingUtilities.invokeLater(() -> {
			try {
				complexStructure.setName("NewComplexStructure");
			}
			catch (UsrException e) {
				Assert.fail();
			}
		});
		waitForPostedSwingRunnables();
		assertEquals(complexStructure.getDataTypePath(), model.getOriginalDataTypePath());
		assertTrue(!complexStructure.getPathName().equals(model.viewComposite.getPathName()));
		assertEquals("EditedComplexStructure", model.getCompositeName());
	}

	@Test
	public void testComponentDataTypeReplaced() throws Exception {
		init(complexStructure, pgmTestCat);

		int numComps = model.getNumComponents();
		int len = model.getLength();
		// Clone the data types we want to hold onto for comparison later, since reload can close the viewDTM.
		DataType dt15 = getDataType(15).clone(programDTM);
		DataType dt16 = getDataType(16).clone(programDTM);
		DataType dt18 = getDataType(18).clone(programDTM);
		DataType dt19 = getDataType(19).clone(programDTM);
		DataType dt20 = getDataType(20).clone(programDTM);
		String dt21Name = getDataType(21).getName();
		DataType dt22 = getDataType(22).clone(programDTM);
		assertEquals(87, complexStructure.getComponent(16).getDataType().getLength());
		assertEquals(29, complexStructure.getComponent(19).getDataType().getLength());
		assertEquals(24, complexStructure.getComponent(20).getDataType().getLength());
		assertEquals(29, complexStructure.getComponent(21).getDataType().getLength());
		assertEquals(87, complexStructure.getComponent(16).getLength());
		assertEquals(29, complexStructure.getComponent(19).getLength());
		assertEquals(24, complexStructure.getComponent(20).getLength());
		assertEquals(29, complexStructure.getComponent(21).getLength());
		assertEquals(len, complexStructure.getLength());
		assertEquals(23, complexStructure.getNumComponents());
		assertEquals(87, getDataType(16).getLength());
		assertEquals(29, getDataType(19).getLength());
		assertEquals(24, getDataType(20).getLength());
		assertEquals(29, getDataType(21).getLength());
		assertEquals(87, model.getComponent(16).getLength());
		assertEquals(29, model.getComponent(19).getLength());
		assertEquals(24, model.getComponent(20).getLength());
		assertEquals(29, model.getComponent(21).getLength());
		assertEquals(len, model.getLength());

		final Structure newSimpleStructure =
			new StructureDataType(new CategoryPath("/aa/bb"), "simpleStructure", 10);
		newSimpleStructure.add(new PointerDataType(), 8);
		newSimpleStructure.replace(2, new CharDataType(), 1);

		DataType dt17 = new ArrayDataType(new PointerDataType(newSimpleStructure, 8, model.viewDTM),
			7, -1, model.viewDTM);

		// Change the struct.  simpleStructure was 29 bytes, but now 18.
		runSwing(() -> {
			try {
				programDTM.replaceDataType(simpleStructure, newSimpleStructure, true);
			}
			catch (DataTypeDependencyException e) {
				Assert.fail(e.getMessage());
			}
		}, false);
		Thread.sleep(2000);
		waitForPostedSwingRunnables();

//		// Verify the Reload Structure Editor? dialog is displayed.
//		Window dialog = env.waitForWindow("Reload Structure Editor?", 1000);
//		assertNotNull(dialog);
//		pressButtonByText(dialog, "No");
//		dialog.dispose();
//		dialog = null;

		// Check that the viewer now has the modified struct.
		assertEquals(54, getDataType(16).getLength());
		assertEquals(18, getDataType(52).getLength());
		assertEquals(24, getDataType(64).getLength());
		assertEquals(18, getDataType(65).getLength());
		assertEquals(54, model.getComponent(16).getLength());
		assertEquals(18, model.getComponent(52).getLength());
		assertEquals(24, model.getComponent(64).getLength());
		assertEquals(18, model.getComponent(65).getLength());
		assertTrue(dt15.isEquivalent(getDataType(15)));
		assertEquals(dt16.getName(), getDataType(16).getName());
		assertTrue(dt17.isEquivalent(getDataType(50)));
		assertTrue(dt18.isEquivalent(getDataType(51)));
		assertEquals(dt19.getName(), getDataType(52).getName());
		assertEquals(dt20.getName(), getDataType(64).getName());
		assertEquals(dt21Name, getDataType(65).getName());
		assertTrue(dt22.isEquivalent(getDataType(77)));
		assertEquals(len, model.getLength());
		assertEquals(numComps + (11 * 5), model.getNumComponents());
	}

	@Test
	public void testModifiedEditedDataTypeReplacedYes() throws Exception {
		Window dialog;
		init(complexStructure, pgmTestCat);

		runSwing(() -> {
			try {
//					model.setLocked(false);
				model.insert(model.getNumComponents(), new ByteDataType(), 1);
				model.insert(model.getNumComponents(), new PointerDataType(), 4);
			}
			catch (UsrException e) {
				Assert.fail(e.getMessage());
			}
		});

		final Structure newComplexStructure =
			new StructureDataType(pgmTestCat.getCategoryPath(), complexStructure.getName(), 0);
		newComplexStructure.add(new Pointer64DataType(), 8);
		newComplexStructure.add(new CharDataType(), 1);

		programDTM.replaceDataType(complexStructure, newComplexStructure, true);
		waitForPostedSwingRunnables();
		DataType origCopy = newComplexStructure.clone(null);

		// Verify the Reload Structure Editor? dialog is displayed.
		dialog = env.waitForWindow("Reload Structure Editor?", 1000);
		assertNotNull(dialog);
		pressButtonByText(dialog, "Yes");
		dialog.dispose();
		dialog = null;

		assertEquals(((Structure) origCopy).getNumComponents(), model.getNumComponents());
		assertTrue(origCopy.isEquivalent(model.viewComposite));
	}

	@Test
	public void testModifiedEditedDataTypeReplacedNo() throws Exception {
		Window dialog;
		init(complexStructure, pgmTestCat);

		runSwing(() -> {
			try {
//					model.setLocked(false);
				model.insert(model.getNumComponents(), new ByteDataType(), 1);
				model.insert(model.getNumComponents(), new PointerDataType(), 4);
			}
			catch (UsrException e) {
				Assert.fail(e.getMessage());
			}
		});
		DataType viewCopy = model.viewComposite.clone(null);

		final Structure newComplexStructure =
			new StructureDataType(pgmTestCat.getCategoryPath(), complexStructure.getName(), 0);
		newComplexStructure.add(new PointerDataType(), 8);
		newComplexStructure.add(new CharDataType(), 1);

		programDTM.replaceDataType(complexStructure, newComplexStructure, true);
		waitForPostedSwingRunnables();

		// Verify the Reload Structure Editor? dialog is displayed.
		dialog = env.waitForWindow("Reload Structure Editor?", 1000);
		assertNotNull(dialog);
		pressButtonByText(dialog, "No");
		dialog.dispose();
		dialog = null;

		assertEquals(((Structure) viewCopy).getNumComponents(), model.getNumComponents());
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
	}

	@Test
	public void testUnModifiedEditedDataTypeReplaced() throws Exception {
		init(complexStructure, pgmTestCat);

		Structure newComplexStructure =
			new StructureDataType(pgmTestCat.getCategoryPath(), complexStructure.getName(), 0);
		newComplexStructure.add(new PointerDataType(null, 8), 8);
		newComplexStructure.add(new CharDataType(), 1);

		assertTrue(complexStructure.isEquivalent(model.viewComposite));
		programDTM.replaceDataType(complexStructure, newComplexStructure, true);
		waitForPostedSwingRunnables();
		assertTrue(newComplexStructure.isEquivalent(model.viewComposite));
	}

}
