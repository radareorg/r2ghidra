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
package ghidra.graph.viewer.options;

import docking.DockingUtils;

public class VisualGraphOptions {

	public static final String SHOW_ANIMATION_OPTIONS_KEY = "Use Animation";
	public static final String SHOW_ANIMATION_DESCRIPTION = "Signals to the Function Graph to " +
		"use animated transitions for certain operations, like navigation.";

	public static final String USE_MOUSE_RELATIVE_ZOOM_KEY = "Use Mouse-relative Zoom";
	public static final String USE_MOUSE_RELATIVE_ZOOM_DESCRIPTION = "When true the Function " +
		"Graph will perform zoom operations relative to the mouse point.";

	public static final String USE_CONDENSED_LAYOUT_KEY = "Use Condensed Layout";
	public static final String USE_CONDENSED_LAYOUT_DESCRIPTION = "Place vertices as close " +
		"together as possible.  For example, when true, the graph will use little spacing " +
		"between vertices.  Each layout will handle this option differently.";

	public static final String SCROLL_WHEEL_PANS_KEY = "Scroll Wheel Pans";
	public static final String SCROLL_WHEEL_PANS_DESCRIPTION = "When enabled the mouse scroll " +
		"wheel will pan the view vertically.  When not enabled, you must hold the <b>" +
		DockingUtils.CONTROL_KEY_NAME + "</b> key while using the mouse wheel";

	public static final String USE_STICKY_SELECTION_KEY = "Use Sticky Selection";
	public static final String USE_STICKY_SELECTION_DESCRIPTION = "When enabled " +
		"Selecting code units in one vertex will not clear the selection in another.  When " +
		"disabled, every new selection clears the previous selection <b>unless the Control</b>" +
		"key is pressed.";

	public static final String VIEW_RESTORE_OPTIONS_KEY = "View Settings";
	public static final String VIEW_RESTORE_OPTIONS_DESCRIPTION = "Dictates how the view of " +
		"new graphs and already rendered graphs are zoomed and positioned.  See the help for " +
		"more details.";

	protected boolean useAnimation = true;
	protected boolean scrollWheelPans = false;

	/**
	 * This should be true by default when 'scrollWheelPans' is true by default
	 */
	protected boolean useMouseRelativeZoom = true;
	protected boolean useCondensedLayout = true;

	protected ViewRestoreOption viewRestoreOption = ViewRestoreOption.START_FULLY_ZOOMED_OUT;

	public boolean getScrollWheelPans() {
		return scrollWheelPans;
	}

	public ViewRestoreOption getViewRestoreOption() {
		return viewRestoreOption;
	}

	public void setUseAnimation(boolean useAnimation) {
		this.useAnimation = useAnimation;
	}

	public boolean useAnimation() {
		return useAnimation;
	}

	public boolean useMouseRelativeZoom() {
		return useMouseRelativeZoom;
	}

	public boolean useCondensedLayout() {
		return useCondensedLayout;
	}

}
