/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.provider.matchtable;

import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTSession;

import java.util.List;

import docking.ActionContext;

public class VTMatchContext extends ActionContext {

	private final List<VTMatch> selectedMatches;
	private final VTSession session;

	public VTMatchContext(VTMatchTableProvider provider, List<VTMatch> selectedMatches,
			VTSession session) {
		super(provider, null);
		this.selectedMatches = selectedMatches;
		this.session = session;
	}

	public List<VTMatch> getSelectedMatches() {
		return selectedMatches;
	}

	public VTSession getSession() {
		return session;
	}
}
