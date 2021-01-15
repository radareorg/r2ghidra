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
package ghidra.graph.viewer.event.mouse;

import java.awt.event.MouseEvent;

import docking.DockingUtils;
import edu.uci.ics.jung.visualization.control.ScalingGraphMousePlugin;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.options.VisualGraphOptions;

/**
 * Overridden implementation that allows us to change scaling behavior through options.  This 
 * class works on the opposite modifier setup as FunctionGraphScrollWheelPanningPlugin.
 */
public class VisualGraphScalingGraphMousePlugin<V extends VisualVertex, E extends VisualEdge<V>>
		extends ScalingGraphMousePlugin implements VisualGraphMousePlugin<V, E> {

	public VisualGraphScalingGraphMousePlugin() {
		// no modifiers set here--we will always check ourselves
		super(new VisualGraphScalingControl(), 0, 1 / 1.1f, 1.1f);
		setZoomAtMouse(true); // this is a default that can be overridden in our scaler
	}

	@Override
	public boolean checkModifiers(MouseEvent e) {
		return isZoomModifiers(e);
	}

	// see also FunctionGraphScrollWheelPanningPlugin
	private boolean isZoomModifiers(MouseEvent e) {

		GraphViewer<V, E> viewer = getGraphViewer(e);
		if (viewer == null) {
			return false;
		}

		// TODO for deprecated usage note, see the VisualGraphMousePlugin interface
		VisualGraphOptions options = viewer.getOptions();
		boolean scrollWheelPans = options.getScrollWheelPans();
		int scrollWheelModifierToggle = DockingUtils.CONTROL_KEY_MODIFIER_MASK_DEPRECATED;
		int eventModifiers = e.getModifiers();
		if (scrollWheelPans) {
			// scrolling will zoom if modified (unmodified in this case means to pan)
			return (scrollWheelModifierToggle & eventModifiers) == scrollWheelModifierToggle;
		}

		// scrolling *will* zoom only when not modified (modified in this case means to pan)
		return !((scrollWheelModifierToggle & eventModifiers) == scrollWheelModifierToggle);
	}
}
