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
package ghidra.app.plugin.core.function.editor;

import java.awt.*;
import java.awt.event.*;
import java.util.EventObject;

import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.table.TableCellEditor;

import docking.DialogComponentProvider;
import docking.widgets.DropDownSelectionTextField;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.program.model.data.DataType;
import ghidra.util.MessageType;
import ghidra.util.data.DataTypeParser;

class ParameterDataTypeCellEditor extends AbstractCellEditor implements TableCellEditor {
	private DataTypeSelectionEditor editor;
	private DropDownSelectionTextField<DataType> textField;
	private JButton dataTypeChooserButton;
	private DataType dt;

	private JPanel editorPanel;
	private DataTypeManagerService service;
	private DialogComponentProvider dialog;

	ParameterDataTypeCellEditor(DialogComponentProvider dialog, DataTypeManagerService service) {
		this.dialog = dialog;
		this.service = service;

	}

	@Override
	public Component getTableCellEditorComponent(JTable table1, Object value, boolean isSelected,
			int row, int column) {
		init();

		dt = (DataType) value;

		editor.setCellEditorValue(dt);

		return editorPanel;
	}

	private void init() {
		editor = new DataTypeSelectionEditor(service, -1, DataTypeParser.AllowedDataTypes.ALL);
		editor.setTabCommitsEdit(true);
		editor.setConsumeEnterKeyPress(false); // we want the table to handle Enter key presses

		textField = editor.getDropDownTextField();
		editor.addCellEditorListener(new CellEditorListener() {
			@Override
			public void editingCanceled(ChangeEvent e) {
				cancelCellEditing();
			}

			@Override
			public void editingStopped(ChangeEvent e) {
				stopCellEditing();
			}
		});

		// force a small button for the table's cell editor
		dataTypeChooserButton = new JButton("...") {
			@Override
			public Dimension getPreferredSize() {
				Dimension preferredSize = super.getPreferredSize();
				preferredSize.width = 15;
				return preferredSize;
			}
		};

		dataTypeChooserButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {

				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						DataType dataType = service.getDataType((String) null);
						if (dataType != null) {
							editor.setCellEditorValue(dataType);
							editor.stopCellEditing();
						}
						else {
							editor.cancelCellEditing();
						}
					}
				});
			}
		});

		FocusAdapter focusListener = new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				textField.selectAll();
				textField.removeFocusListener(this);
			}
		};
		textField.addFocusListener(focusListener);

		editorPanel = new JPanel(new BorderLayout());
		editorPanel.add(textField, BorderLayout.CENTER);
		editorPanel.add(dataTypeChooserButton, BorderLayout.EAST);
	}

	/**
	 * @return text field associated with the generated component.  Null will 
	 * be returned if getTableCellEditorComponent method has not yet been invoked. 
	 */
	public DropDownSelectionTextField<DataType> getTextField() {
		return textField;
	}

	/**
	 * @return chooser button '...' associated with the generated component.  Null will 
	 * be returned if getTableCellEditorComponent method has not yet been invoked. 
	 */
	public JButton getChooserButton() {
		return dataTypeChooserButton;
	}

	@Override
	public Object getCellEditorValue() {
		return dt;
	}

	@Override
	public boolean stopCellEditing() {

		try {
			DataType dataType = editor.getCellEditorValueAsDataType();
			dialog.clearStatusText();
			if (dataType == null) {
				String text = editor.getCellEditorValueAsText();
				dialog.setStatusText("Invalid data type: " + text, MessageType.ERROR);
				return false;
			}
			if (dataType.equals(dt)) {
				fireEditingCanceled(); // user picked the same datatype
			}
			else {
				dt = dataType;
				fireEditingStopped();
			}
		}
		// We have to catch special cases where users enter param types that have an 
		// invalid format, not just an invalid value.  ie: "a/b/c" is invalid and will
		// generate an exception; if we don't catch it here, the exception will propagate
		// till the user is presented with an error dialog containing a stack trace.  
		// Instead, catch it and display error text in the status field.	
		//
		// This will be generated by the editor.getCellEditorValueAsDataType() call.
		catch (IllegalArgumentException ex) {
			String text = editor.getCellEditorValueAsText();
			dialog.setStatusText("Invalid data type: " + text, MessageType.ERROR);
			return false;
		}
		return true;
	}

	// only double-click edits
	@Override
	public boolean isCellEditable(EventObject anEvent) {
		if (anEvent instanceof MouseEvent) {
			return ((MouseEvent) anEvent).getClickCount() >= 2;
		}
		return true;
	}

	DataTypeSelectionEditor getEditor() {
		return editor;
	}
}
