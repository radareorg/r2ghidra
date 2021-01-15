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
import ghidra.app.plugin.core.hover.AbstractReferenceHover;
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

public class ReferenceDecompilerHover extends AbstractReferenceHover
		implements DecompilerHoverService {

	protected static final String NAME = "Decompiler Reference Viewer";

	private static final String DESCRIPTION =
		"Shows \"referred to\" code and data from the decompiler.";

	private static final int PRIORITY = 25;

	public ReferenceDecompilerHover(PluginTool tool) {
		super(tool, PRIORITY);
	}

	@Override
	public void initializeOptions() {
		options = tool.getOptions(GhidraOptions.CATEGORY_DECOMPILER_POPUPS);

		options.setOptionsHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "MouseHover"));
		HelpLocation help = new HelpLocation(HelpTopics.CODE_BROWSER, "ReferenceHover");
		options.getOptions(NAME).setOptionsHelpLocation(help);

		options.registerOption(NAME, true, null, DESCRIPTION);

		options.registerOption(NAME + Options.DELIMITER + "Dialog Height", 400, help,
			"Height of the popup window");
		options.registerOption(NAME + Options.DELIMITER + "Dialog Width", 600, help,
			"Width of the popup window");

		setOptions(options, NAME);
		options.addOptionsChangeListener(this);
	}

	@Override
	public JComponent getHoverComponent(Program program, ProgramLocation location,
			FieldLocation fieldLocation, Field field) {

		if (!enabled || location == null) {
			return null;
		}

		Address refAddr = location.getRefAddress();
		if (refAddr == null) {
			return null;
		}
		Function other = program.getListing().getFunctionAt(refAddr);
		if (other != null) {
			return null;
		}
		return super.getHoverComponent(program, location, fieldLocation, field);

	}

}
