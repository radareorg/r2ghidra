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

import java.awt.event.MouseEvent;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class BitFieldEditorDialog extends DialogComponentProvider {

	private static final Icon ADD_ICON = ResourceManager.loadImage("images/Plus.png");
	private static final Icon EDIT_ICON = ResourceManager.loadImage("images/move.png");
	private static final Icon DELETE_ICON = ResourceManager.loadImage("images/edit-delete.png");

	private DataTypeManagerService dtmService;
	private Composite composite;
	private CompositeChangeListener listener;

	private BitFieldEditorPanel bitFieldEditorPanel; // for unaligned use case

	BitFieldEditorDialog(Composite composite, DataTypeManagerService dtmService, int editOrdinal,
			CompositeChangeListener listener) {
		super("Edit " + getCompositeType(composite) + " Bitfield");
		this.composite = composite;
		this.listener = listener;
		this.dtmService = dtmService;
		addButtons();
		addWorkPanel(buildWorkPanel(editOrdinal));
		setRememberLocation(false);
		setRememberSize(false);

		addActions();

		setHelpLocation(new HelpLocation("DataTypeEditors", "Structure_Bitfield_Editor"));
	}

	private void addButtons() {
		addOKButton();
		addCancelButton();
		if (composite instanceof Structure) {
			addApplyButton();
			setApplyEnabled(false);
		}
	}

	private static DataTypeComponent getEditComponent(ActionContext context, boolean bitFieldOnly) {
		if (!(context instanceof BitFieldEditorPanel.BitFieldEditorContext)) {
			return null;
		}
		BitFieldEditorPanel.BitFieldEditorContext editorContext =
			(BitFieldEditorPanel.BitFieldEditorContext) context;
		DataTypeComponent dtc = editorContext.getSelectedComponent();
		if (dtc != null && (!bitFieldOnly || dtc.isBitFieldComponent())) {
			return dtc;
		}
		return null;
	}

	private class EditBitFieldAction extends DockingAction {

		EditBitFieldAction() {
			super("Edit Bitfield", "BitFieldEditorDialog");
			setPopupMenuData(new MenuData(new String[] { getName() }, EDIT_ICON));
			setHelpLocation(new HelpLocation("DataTypeEditors", "Structure_Editor_Edit_Bitfield"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			DataTypeComponent bitfieldDtc = getEditComponent(context, true);
			if (bitfieldDtc == null || !bitFieldEditorPanel.endCurrentEdit()) {
				return;
			}
			initEdit(bitfieldDtc.getOrdinal(), true);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return getEditComponent(context, true) != null;
		}
	}

	private class AddBitFieldAction extends DockingAction {

		AddBitFieldAction() {
			super("Add Bitfield", "BitFieldEditorDialog");
			setPopupMenuData(new MenuData(new String[] { getName() }, ADD_ICON));
			setHelpLocation(new HelpLocation("DataTypeEditors", "Structure_Editor_Add_Bitfield"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (!bitFieldEditorPanel.endCurrentEdit()) {
				return;
			}
			BitFieldEditorPanel.BitFieldEditorContext editorContext =
				(BitFieldEditorPanel.BitFieldEditorContext) context;

			bitFieldEditorPanel.initAdd(null, editorContext.getAllocationOffset(),
				editorContext.getSelectedBitOffset(), true);
			setApplyEnabled(true);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return (context instanceof BitFieldEditorPanel.BitFieldEditorContext) &&
				!bitFieldEditorPanel.isAdding();
		}
	}

	private class DeleteComponentAction extends DockingAction {

		DeleteComponentAction() {
			super("Delete", "BitFieldEditorDialog");
			setPopupMenuData(new MenuData(new String[] { getName() }, DELETE_ICON));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			DataTypeComponent bitfieldDtc = getEditComponent(context, false);
			if (bitfieldDtc == null) {
				return;
			}
			int ordinal = bitfieldDtc.getOrdinal();
			composite.delete(ordinal);
			bitFieldEditorPanel.componentDeleted(ordinal);
			if (listener != null) {
				listener.componentChanged(ordinal);
			}
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return getEditComponent(context, false) != null;
		}
	}

	private void addActions() {
		addAction(new AddBitFieldAction());
		addAction(new EditBitFieldAction());
		addAction(new DeleteComponentAction());
	}

	@Override
	protected void applyCallback() {
		if (bitFieldEditorPanel.isEditing() && bitFieldEditorPanel.apply(listener)) {
			setApplyEnabled(false);
		}
	}

	@Override
	protected void okCallback() {
		if (!bitFieldEditorPanel.isEditing() || bitFieldEditorPanel.apply(listener)) {
			close();
		}
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		ActionContext context = bitFieldEditorPanel.getActionContext(event);
		if (context != null) {
			return context;
		}
		return super.getActionContext(event);
	}

	@Override
	protected void cancelCallback() {
		// TODO: Should we cancel without asking?
		if (!bitFieldEditorPanel.endCurrentEdit()) {
			return;
		}
		super.cancelCallback();
	}

	private JComponent buildWorkPanel(int editOrdinal) {
		bitFieldEditorPanel = new BitFieldEditorPanel(composite, dtmService);
		if (editOrdinal < 0) {
			initAdd(-editOrdinal - 1);
		}
		else {
			initEdit(editOrdinal, false);
		}
		return bitFieldEditorPanel;
	}

	private static String getCompositeType(Composite composite) {
		// currently supports unaligned case only!
		if (composite.isInternallyAligned()) {
			throw new IllegalArgumentException("Aligned use not supported");
		}
		String alignmentMode = composite.isInternallyAligned() ? "Aligned" : "Unaligned";
		String type = (composite instanceof Union) ? "Union" : "Structure";
		return alignmentMode + " " + type;
	}

	private void initAdd(int ordinal) {
		DataType baseDataType = null;
		int offset = 0;
		if (ordinal < composite.getNumComponents()) {
			DataTypeComponent dtc = composite.getComponent(ordinal);
			offset = dtc.getOffset();
			if (dtc.isBitFieldComponent()) {
				baseDataType = ((BitFieldDataType) dtc.getDataType()).getBaseDataType();
			}
		}
		else if (!composite.isNotYetDefined()) {
			offset = composite.getLength();
		}

		// use previous or default base datatype
		bitFieldEditorPanel.initAdd(baseDataType, offset, 0, false);
		setApplyEnabled(true);
	}

	private void initEdit(int editOrdinal, boolean useExistingAllocationSize)
			throws ArrayIndexOutOfBoundsException {
		DataTypeComponent dtc = composite.getComponent(editOrdinal);
		if (!dtc.isBitFieldComponent()) {
			throw new IllegalArgumentException("editOrdinal does not correspond to bitfield");
		}
		bitFieldEditorPanel.initEdit(dtc, getPreferredAllocationOffset(dtc),
			useExistingAllocationSize);
		setApplyEnabled(true);
	}

	static int getPreferredAllocationOffset(DataTypeComponent bitfieldDtc) {
		Composite composite = (Composite) bitfieldDtc.getParent();
		if (composite instanceof Union) {
			return 0;
		}

		BitFieldDataType bitfieldDt = (BitFieldDataType) bitfieldDtc.getDataType();
		int offset = bitfieldDtc.getOffset();
		int baseTypeSize = bitfieldDt.getBaseTypeSize();
		if (bitfieldDtc.getLength() >= baseTypeSize) {
			return offset; // do not adjust
		}

		DataOrganization dataOrganization = composite.getDataOrganization();

		// Assume a reasonable alignment in identifying aligned offset
		int alignment = CompositeAlignmentHelper.getPackedAlignment(dataOrganization,
			Composite.NOT_PACKING, bitfieldDt.getBaseDataType(), bitfieldDt.getBaseTypeSize());

		int adjustedOffset = offset - (offset % alignment);

		// only adjust if bitfield fits within aligned offset
		if (bitfieldDtc.getEndOffset() <= (adjustedOffset + baseTypeSize - 1)) {
			return adjustedOffset;
		}

		return offset;
	}
}
