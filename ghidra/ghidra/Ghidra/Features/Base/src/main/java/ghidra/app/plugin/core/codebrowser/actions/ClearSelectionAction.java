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
package ghidra.app.plugin.core.codebrowser.actions;

import docking.ActionContext;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.util.HelpTopics;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

/**
 * Action for clearing the current selection
 */
public class ClearSelectionAction extends CodeViewerContextAction {

	public ClearSelectionAction(String owner) {
		super("Clear Selection", owner);
		setSupportsDefaultToolContext(true);
		setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_SELECTION, "&Clear Selection" }, null, "Select"));

		setHelpLocation(new HelpLocation(HelpTopics.SELECTION, getName()));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		CodeViewerProvider provider = (CodeViewerProvider) context.getComponentProvider();
		provider.setSelection(new ProgramSelection());
	}
}
