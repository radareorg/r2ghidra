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
package ghidra.graph.visualization;

import javax.swing.JComponent;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

/**
 * provided a JComponent for the ProgramGraph visualization
 */
public class DefaultGraphDisplayComponentProvider extends ComponentProviderAdapter {

	static final String WINDOW_GROUP = "ProgramGraph";
	private static final String WINDOW_MENU_GROUP_NAME = "Graph";
	private final DefaultGraphDisplay display;

	DefaultGraphDisplayComponentProvider(DefaultGraphDisplay display, PluginTool pluginTool) {
		super(pluginTool, "Graph", "DefaultGraphDisplay");
		this.display = display;
		setHelpLocation(new HelpLocation("GraphServices", "Default_Graph_Display"));
		setIcon(DefaultDisplayGraphIcons.PROGRAM_GRAPH_ICON);
		setTransient();
		setWindowGroup(WINDOW_GROUP);
		setSubTitle(Integer.toString(display.getId()));
	}

	@Override
	public String getWindowSubMenuName() {
		return WINDOW_MENU_GROUP_NAME;
	}

	@Override
	public JComponent getComponent() {
		return display.getComponent();
	}

	@Override
	public void closeComponent() {
		super.closeComponent();
		display.close();
	}
}
