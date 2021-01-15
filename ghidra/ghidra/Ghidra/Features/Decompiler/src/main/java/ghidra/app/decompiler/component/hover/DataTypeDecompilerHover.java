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
package ghidra.app.decompiler.component.hover;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.plugin.core.hover.AbstractDataTypeHover;
import ghidra.app.util.ToolTipUtils;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.ProgramLocation;

public class DataTypeDecompilerHover extends AbstractDataTypeHover
		implements DecompilerHoverService {

	private static final String NAME = "Data Type Display";
	private static final String DESCRIPTION =
		"Show data type contents when hovering over a type name.";
	private static final int PRIORITY = 20;

	protected DataTypeDecompilerHover(PluginTool tool) {
		super(tool, PRIORITY);
	}

	@Override
	public void initializeOptions() {
		options = tool.getOptions(GhidraOptions.CATEGORY_DECOMPILER_POPUPS);
		options.registerOption(NAME, true, null, DESCRIPTION);
		setOptions(options, NAME);
		options.addOptionsChangeListener(this);
	}

	@Override
	public void setOptions(Options options, String optionName) {
		if (optionName.equals(NAME)) {
			enabled = options.getBoolean(NAME, true);
		}
	}

	@Override
	public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
			FieldLocation fieldLocation, Field field) {

		if (!enabled) {
			return null;
		}

		if (!(field instanceof ClangTextField)) {
			return null;
		}

		ClangToken token = ((ClangTextField) field).getToken(fieldLocation);

		DataType dt = getDataType(token);
		if (dt == null) {
			dt = getDataType(token.Parent());
		}

		if (dt != null) {
			String toolTipText = ToolTipUtils.getToolTipText(dt);
			return createTooltipComponent(toolTipText);
		}
		return null;

	}

	private DataType getDataType(ClangNode node) {

		if (node instanceof ClangVariableDecl) {
			return ((ClangVariableDecl) node).getDataType();
		}

		if (node instanceof ClangReturnType) {
			return ((ClangReturnType) node).getDataType();
		}

		if (node instanceof ClangTypeToken) {
			return ((ClangTypeToken) node).getDataType();
		}

		if (node instanceof ClangVariableToken) {
			Varnode vn = ((ClangVariableToken) node).getVarnode();
			if (vn != null) {
				HighVariable high = vn.getHigh();
				if (high != null) {
					return high.getDataType();
				}
			}
		}

		return null;
	}
}
