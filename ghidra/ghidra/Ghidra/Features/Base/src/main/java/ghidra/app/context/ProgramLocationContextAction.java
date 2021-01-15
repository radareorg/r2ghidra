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
package ghidra.app.context;

import java.util.Set;

import docking.ActionContext;
import docking.action.DockingAction;

public abstract class ProgramLocationContextAction extends DockingAction {
	
	public ProgramLocationContextAction(String name, String owner) {
		super(name, owner);
	}
	
	@Override
    public boolean isEnabledForContext(ActionContext context) {
    	Object contextObject = context.getContextObject();
		if (!(contextObject instanceof ProgramLocationActionContext)) {
			return false;
		}
		return isEnabledForContext((ProgramLocationActionContext)contextObject);
	}

	@Override
	public void actionPerformed(ActionContext actionContext) {
		actionPerformed((ProgramLocationActionContext)actionContext.getContextObject());
	}
	
	@Override
	public boolean isValidContext(ActionContext context) {
		if (context instanceof ProgramLocationActionContext) {
			return isValidContext((ProgramLocationActionContext)context);
		}
		return false;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (context instanceof ProgramLocationActionContext) {
			return isAddToPopup((ProgramLocationActionContext)context);
		}
		return false;
	}

	protected boolean isAddToPopup(ProgramLocationActionContext context) {
		return true;
	}

	protected boolean isValidContext(ProgramLocationActionContext context) {
		return isEnabledForContext(context);
	}

	protected boolean isEnabledForContext(ProgramLocationActionContext context) {
		return true;
	}

	protected void actionPerformed(ProgramLocationActionContext context) {
		
	}
	
	@Override
	public boolean shouldAddToWindow(boolean isMainWindow, Set<Class<?>> contextTypes) {
		for (Class<?> class1 : contextTypes) {
			if (ProgramLocationActionContext.class.isAssignableFrom(class1)) {
				return true;
			}
		}
		return false;
	}
}
