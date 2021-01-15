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
package ghidra.program.database.module;

import java.io.IOException;
import java.util.*;

import db.Record;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.Lock;
import ghidra.util.exception.*;

/**
 *
 * Database implementation for Module.
 *  
 * 
 */
class ModuleDB extends DatabaseObject implements ProgramModule {

	private Record record;
	private ModuleManager moduleMgr;
	private GroupDBAdapter adapter;
	private int childCount; // cache the count so we don't have to access 
							// database records
	private Lock lock;

	/**
	 * 
	 * Constructor
	 * @param moduleMgr module manager
	 * @param cache ModuleDB cache
	 * @param record database record for this module
	 */
	ModuleDB(ModuleManager moduleMgr, DBObjectCache<ModuleDB> cache, Record record) {
		super(cache, record.getKey());
		this.moduleMgr = moduleMgr;
		this.record = record;
		adapter = moduleMgr.getGroupDBAdapter();
		updateChildCount();
		lock = moduleMgr.getLock();
	}

	@Override
	protected boolean refresh() {
		try {
			Record rec = adapter.getModuleRecord(key);
			if (rec != null) {
				record = rec;
				childCount = 0;
				try {
					long[] keys = adapter.getParentChildKeys(key, TreeManager.PARENT_ID_COL);
					childCount = keys.length;
				}
				catch (IOException e) {
					moduleMgr.dbError(e);
				}
				return true;
			}
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#add(ghidra.program.model.listing.ProgramFragment)
	 */
	public void add(ProgramFragment fragment) throws DuplicateGroupException {
		lock.acquire();
		try {
			checkDeleted();
			FragmentDB frag = (FragmentDB) fragment;
			long fragID = frag.getKey();
			// add a row to the parent/child table
			Record parentChildRecord = adapter.getParentChildRecord(key, -fragID);
			if (parentChildRecord != null) {
				throw new DuplicateGroupException(frag.getName() + " already exists a child of " +
					getName());
			}

			Record pcRec = adapter.addParentChildRecord(key, -fragID);
			updateChildCount();
			updateOrderField(pcRec);
			moduleMgr.fragmentAdded(key, frag);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#add(ghidra.program.model.listing.ProgramModule)
	 */
	public void add(ProgramModule module) throws CircularDependencyException, DuplicateGroupException {

		lock.acquire();
		try {
			checkDeleted();
			ModuleDB moduleDB = (ModuleDB) module;
			long moduleID = moduleDB.getKey();

			Record parentChildRecord = adapter.getParentChildRecord(key, moduleID);
			if (parentChildRecord != null) {
				throw new DuplicateGroupException(module.getName() + " already exists a child of " +
					getName());
			}
			if (moduleMgr.isDescendant(key, moduleID)) {
				throw new CircularDependencyException(getName() + " is already a descendant of " +
					module.getName());
			}

			Record pcRec = adapter.addParentChildRecord(key, moduleID);
			updateChildCount();
			updateOrderField(pcRec);
			moduleMgr.moduleAdded(key, module);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#contains(ghidra.program.model.listing.ProgramFragment)
	 */
	public boolean contains(ProgramFragment fragment) {
		if (!(fragment instanceof FragmentDB)) {
			return false;
		}
		FragmentDB frag = (FragmentDB) fragment;
		if (moduleMgr != frag.getModuleManager()) {
			return false;
		}
		return contains(-frag.getKey());
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#contains(ghidra.program.model.listing.ProgramModule)
	 */
	public boolean contains(ProgramModule module) {
		if (!(module instanceof ModuleDB)) {
			return false;
		}
		ModuleDB moduleDB = (ModuleDB) module;
		if (moduleMgr != moduleDB.moduleMgr) {
			return false;
		}
		return contains(moduleDB.getKey());
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#createFragment(java.lang.String)
	 */
	public ProgramFragment createFragment(String fragmentName) throws DuplicateNameException {

		lock.acquire();
		try {
			checkDeleted();
			Record parentChildRecord = adapter.createFragment(key, fragmentName);
			FragmentDB frag = moduleMgr.getFragmentDB(parentChildRecord);
			Record pcRec = adapter.getParentChildRecord(key, -frag.getKey());
			updateChildCount();
			updateOrderField(pcRec);
			moduleMgr.fragmentAdded(key, frag);
			return frag;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#createModule(java.lang.String)
	 */
	public ProgramModule createModule(String moduleName) throws DuplicateNameException {

		lock.acquire();
		try {
			checkDeleted();
			Record moduleRecord = adapter.createModule(key, moduleName);
			ModuleDB moduleDB = moduleMgr.getModuleDB(moduleRecord);
			Record pcRec = adapter.getParentChildRecord(key, moduleDB.key);
			updateChildCount();
			updateOrderField(pcRec);
			moduleMgr.moduleAdded(key, moduleDB);
			return moduleDB;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#getChildren()
	 */
	public Group[] getChildren() {
		lock.acquire();
		try {
			checkIsValid();
			List<Record> list = getParentChildRecords();
			Group[] kids = new Group[list.size()];
			for (int i = 0; i < list.size(); i++) {
				Record rec = list.get(i);
				long childID = rec.getLongValue(TreeManager.CHILD_ID_COL);
				if (childID < 0) {
					kids[i] = moduleMgr.getFragmentDB(-childID);
				}
				else {
					kids[i] = moduleMgr.getModuleDB(childID);
				}
			}
			childCount = kids.length;
			return kids;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return new Group[0];
	}

	/**
	 * @see ghidra.program.model.listing.Group#getComment()
	 */
	public String getComment() {
		lock.acquire();
		try {
			checkIsValid();
			return record.getString(TreeManager.MODULE_COMMENTS_COL);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#getFirstAddress()
	 */
	public Address getFirstAddress() {
		lock.acquire();
		try {
			checkIsValid();
			return findFirstAddress(this);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#getIndex(java.lang.String)
	 */
	public int getIndex(String name) {
		lock.acquire();
		try {
			checkIsValid();
			Record fragmentRecord = adapter.getFragmentRecord(name);
			Record pcRec = null;
			if (fragmentRecord != null) {
				long fragID = fragmentRecord.getKey();
				pcRec = adapter.getParentChildRecord(key, -fragID);
			}
			else {
				fragmentRecord = adapter.getModuleRecord(name);
				if (fragmentRecord != null) {
					pcRec = adapter.getParentChildRecord(key, fragmentRecord.getKey());
				}
			}
			if (pcRec != null) {
				return pcRec.getIntValue(TreeManager.ORDER_COL);
			}
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return -1;
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#getLastAddress()
	 */
	public Address getLastAddress() {
		lock.acquire();
		try {
			checkIsValid();
			return findLastAddress(this);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#getMaxAddress()
	 */
	public Address getMaxAddress() {
		lock.acquire();
		try {
			checkIsValid();
			return findMaxAddress(this, null);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#getMinAddress()
	 */
	public Address getMinAddress() {
		lock.acquire();
		try {
			checkIsValid();
			return findMinAddress(this, null);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#getAddressSet()
	 */
	public AddressSetView getAddressSet() {
		AddressSet set = new AddressSet();
		Group[] children = getChildren();
		for (int i = 0; i < children.length; i++) {
			if (children[i] instanceof ProgramFragment) {
				set.add((ProgramFragment) children[i]);
			}
			else {
				ProgramModule m = (ProgramModule) children[i];
				set.add(m.getAddressSet());
			}
		}
		return set;
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#getNumChildren()
	 */
	public int getNumChildren() {
		lock.acquire();
		try {
			checkIsValid();
			return childCount;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#isDescendant(ghidra.program.model.listing.ProgramFragment)
	 */
	public boolean isDescendant(ProgramFragment fragment) {
		if (!(fragment instanceof FragmentDB)) {
			return false;
		}
		FragmentDB frag = (FragmentDB) fragment;
		try {
			return moduleMgr.isDescendant(-frag.getKey(), key);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#isDescendant(ghidra.program.model.listing.ProgramModule)
	 */
	public boolean isDescendant(ProgramModule module) {
		if (!(module instanceof ModuleDB)) {
			return false;
		}
		ModuleDB moduleDB = (ModuleDB) module;
		try {
			return moduleMgr.isDescendant(moduleDB.key, key);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#moveChild(java.lang.String, int)
	 */
	public void moveChild(String name, int index) throws NotFoundException {
		lock.acquire();
		try {
			checkDeleted();
			int currentIndex = 0;
			boolean foundName = false;
			Group group = null;

			List<Record> list = getParentChildRecords();
			for (int i = 0; i < list.size(); i++) {
				Record rec = list.get(i);
				long childID = rec.getLongValue(TreeManager.CHILD_ID_COL);
				String childName = null;
				Record childRec = null;
				if (childID < 0) {
					childRec = adapter.getFragmentRecord(-childID);
					childName = childRec.getString(TreeManager.FRAGMENT_NAME_COL);
				}
				else {
					childRec = adapter.getModuleRecord(childID);
					childName = childRec.getString(TreeManager.MODULE_NAME_COL);
				}
				if (childName.equals(name)) {
					foundName = true;
					currentIndex = i;
					if (childID < 0) {
						group = moduleMgr.getFragmentDB(childRec);
					}
					else {
						group = moduleMgr.getModuleDB(childRec);
					}
				}
			}
			if (!foundName) {
				throw new NotFoundException(name + " is not a child of " + getName());
			}
			Record pcRec = list.remove(currentIndex);
			list.add(index, pcRec);
			updateChildOrder(list);

			moduleMgr.childReordered(this, group);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#removeChild(java.lang.String)
	 */
	public boolean removeChild(String name) throws NotEmptyException {

		lock.acquire();
		try {
			checkDeleted();
			Record rec = adapter.getFragmentRecord(name);
			boolean deleteChild = false;

			if (rec != null) {
				// make sure that I am a parent of this child
				long childID = rec.getKey();
				Record pcRec = adapter.getParentChildRecord(key, -childID);
				if (pcRec == null) {
					// check for module record
					return removeModuleRecord(name);
				}
				long[] keys = adapter.getParentChildKeys(-childID, TreeManager.CHILD_ID_COL);
				if (keys.length == 1) {
					FragmentDB frag = moduleMgr.getFragmentDB(childID);
					if (!frag.isEmpty()) {
						throw new NotEmptyException(frag.getName() + " is not empty");
					}
					deleteChild = true;
				}
				return removeChild(childID, pcRec, true, deleteChild);
			}
			return removeModuleRecord(name);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	private boolean removeModuleRecord(String name) throws IOException, NotEmptyException {

		Record rec = adapter.getModuleRecord(name);
		if (rec == null) {
			return false;
		}
		boolean deleteChild = false;
		long childID = rec.getKey();
		Record pcRec = adapter.getParentChildRecord(key, childID);
		if (pcRec == null) {
			return false;
		}
		long[] keys = adapter.getParentChildKeys(childID, TreeManager.CHILD_ID_COL);

		if (keys.length == 1) {
			ProgramModule module = moduleMgr.getModuleDB(childID);
			if (module.getNumChildren() > 0) {
				throw new NotEmptyException(getName() + " is not empty");
			}
			deleteChild = true;
		}

		return removeChild(childID, pcRec, false, deleteChild);
	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#reparent(java.lang.String, ghidra.program.model.listing.ProgramModule)
	 */
	public void reparent(String name, ProgramModule oldParent) throws NotFoundException {

		Group group = null;
		ProgramFragment f = null;

		lock.acquire();
		try {
			checkDeleted();
			long childID;
			ProgramModule m = moduleMgr.getModule(name);
			if (m == null) {
				f = moduleMgr.getFragment(name);
				if (f == null) {
					throw new NotFoundException(name + " was not found as child of " + getName());
				}
				childID = -((FragmentDB) f).getKey();
				group = f;
			}
			else {
				childID = ((ModuleDB) m).key;
				group = m;
			}
			ModuleDB oldModuleDB = (ModuleDB) oldParent;

			Record oldPcRec = adapter.getParentChildRecord(oldModuleDB.key, childID);
			adapter.removeParentChildRecord(oldPcRec.getKey());
			Record newPcRec = adapter.addParentChildRecord(key, childID);
			++childCount;
			updateOrderField(newPcRec);
			oldModuleDB.resetChildOrder();
			moduleMgr.childReparented(group, oldParent.getName(), getName());
		}
		catch (IOException e) {
			moduleMgr.dbError(e);

		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.Group#contains(ghidra.program.model.listing.CodeUnit)
	 */
	public boolean contains(CodeUnit codeUnit) {
		FragmentDB frag = moduleMgr.getFragment(codeUnit);
		if (frag != null) {
			return contains(frag);
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.listing.Group#getName()
	 */
	public String getName() {
		lock.acquire();
		try {
			checkIsValid();
			return record.getString(TreeManager.MODULE_NAME_COL);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.Group#getNumParents()
	 */
	public int getNumParents() {
		lock.acquire();
		try {
			checkIsValid();
			long[] keys = adapter.getParentChildKeys(key, TreeManager.CHILD_ID_COL);
			return keys.length;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return 0;
	}

	/**
	 * @see ghidra.program.model.listing.Group#getParentNames()
	 */
	public String[] getParentNames() {
		return moduleMgr.getParentNames(key);
	}

	/**
	 * @see ghidra.program.model.listing.Group#getParents()
	 */
	public ProgramModule[] getParents() {
		return moduleMgr.getParents(key);
	}

	/**
	 * @see ghidra.program.model.listing.Group#getTreeName()
	 */
	public String getTreeName() {
		return moduleMgr.getTreeName();
	}

	/**
	 * @see ghidra.program.model.listing.Group#setComment(java.lang.String)
	 */
	public void setComment(String comment) {
		lock.acquire();
		try {
			checkDeleted();
			String oldComments = record.getString(TreeManager.MODULE_COMMENTS_COL);
			if (oldComments == null || !oldComments.equals(comment)) {
				record.setString(TreeManager.MODULE_COMMENTS_COL, comment);
				try {
					adapter.updateModuleRecord(record);
					moduleMgr.commentsChanged(oldComments, this);
				}
				catch (IOException e) {
					moduleMgr.dbError(e);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.Group#setName(java.lang.String)
	 */
	public void setName(String name) throws DuplicateNameException {
		lock.acquire();
		try {
			checkDeleted();
			if (key == ModuleManager.ROOT_MODULE_ID) {
				moduleMgr.getProgram().setName(name);
				return;
			}
			Record r = adapter.getModuleRecord(name);
			if (r != null) {
				if (key != r.getKey()) {
					throw new DuplicateNameException(name + " already exists");
				}
				return; // no changes
			}
			if (adapter.getFragmentRecord(name) != null) {
				throw new DuplicateNameException(name + " already exists");
			}
			String oldName = record.getString(TreeManager.MODULE_NAME_COL);
			record.setString(TreeManager.MODULE_NAME_COL, name);
			adapter.updateModuleRecord(record);
			moduleMgr.nameChanged(oldName, this);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	////////////////////////////////////////////////////////////	

	Record getRecord() {
		return record;
	}

	private boolean contains(long childID) {
		try {
			Record rec = adapter.getParentChildRecord(key, childID);
			return rec != null;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		return false;
	}

	private boolean removeChild(long childID, Record pcRec, boolean isFragment, boolean deleteChild)
			throws IOException {

		adapter.removeParentChildRecord(pcRec.getKey());
		String name = null;
		boolean success = true;
		if (isFragment) {
			Record fragRec = adapter.getFragmentRecord(childID);
			name = fragRec.getString(TreeManager.FRAGMENT_NAME_COL);
			if (deleteChild) {
				success = adapter.removeFragmentRecord(childID);
			}
		}
		else {
			Record mrec = adapter.getModuleRecord(childID);
			name = mrec.getString(TreeManager.MODULE_NAME_COL);
			if (deleteChild) {
				success = adapter.removeModuleRecord(childID);
			}
		}
		if (success) {
			resetChildOrder();

			moduleMgr.groupRemoved(this, childID, name, isFragment, deleteChild);
		}
		return success;
	}

	/**
	 * Get sorted list based on child order column.
	 */
	private List<Record> getParentChildRecords() throws IOException {
		long[] keys = adapter.getParentChildKeys(key, TreeManager.PARENT_ID_COL);
		List<Record> list = new ArrayList<Record>();
		Comparator<Record> c = new ParentChildRecordComparator();
		for (int i = 0; i < keys.length; i++) {
			Record rec = adapter.getParentChildRecord(keys[i]);
			int index = Collections.binarySearch(list, rec, c);
			if (index < 0) {
				index = -index - 1;
			}
			list.add(index, rec);
		}
		return list;
	}

	/**
	 * Use the given list to get the child order and update each record.
	 */
	private void updateChildOrder(List<Record> list) throws IOException {
		for (int i = 0; i < list.size(); i++) {
			Record pcRec = list.get(i);
			pcRec.setIntValue(TreeManager.ORDER_COL, i);
			adapter.updateParentChildRecord(pcRec);
		}
	}

	private void resetChildOrder() throws IOException {
		List<Record> list = getParentChildRecords();
		updateChildOrder(list);
		updateChildCount();
	}

	private void updateOrderField(Record pcRec) throws IOException {
		int orderValue = getNumChildren() - 1;
		if (orderValue < 0) {
			orderValue = 0;
		}
		pcRec.setIntValue(TreeManager.ORDER_COL, orderValue);
		adapter.updateParentChildRecord(pcRec);
	}

	private Address findFirstAddress(ModuleDB module) {
		try {
			List<Record> list = module.getParentChildRecords();
			for (int i = 0; i < list.size(); i++) {
				Record rec = list.get(i);
				long childID = rec.getLongValue(TreeManager.CHILD_ID_COL);
				if (childID < 0) {
					FragmentDB frag = moduleMgr.getFragmentDB(-childID);
					if (!frag.isEmpty()) {
						return frag.getMinAddress();
					}
				}
				else {
					ModuleDB m = moduleMgr.getModuleDB(childID);
					Address addr = findFirstAddress(m);
					if (addr != null) {
						return addr;
					}
				}
			}
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		return null;
	}

	private Address findLastAddress(ModuleDB module) {
		try {
			List<Record> list = module.getParentChildRecords();
			for (int i = list.size() - 1; i >= 0; i--) {
				Record rec = list.get(i);
				long childID = rec.getLongValue(TreeManager.CHILD_ID_COL);
				if (childID < 0) {
					FragmentDB frag = moduleMgr.getFragmentDB(-childID);
					if (!frag.isEmpty()) {
						return frag.getMaxAddress();
					}
				}
				else {
					ModuleDB m = moduleMgr.getModuleDB(childID);
					Address addr = findLastAddress(m);
					if (addr != null) {
						return addr;
					}
				}
			}
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		return null;

	}

	private Address findMinAddress(ModuleDB module, Address addr) {
		Address minAddr = addr;

		try {
			List<Record> list = module.getParentChildRecords();
			for (int i = 0; i < list.size(); i++) {
				Record rec = list.get(i);
				long childID = rec.getLongValue(TreeManager.CHILD_ID_COL);
				Address childMinAddr = null;
				if (childID < 0) {
					FragmentDB frag = moduleMgr.getFragmentDB(-childID);
					if (!frag.isEmpty()) {
						childMinAddr = frag.getMinAddress();
					}
				}
				else {
					ModuleDB m = moduleMgr.getModuleDB(childID);
					childMinAddr = findMinAddress(m, addr);
				}
				if (childMinAddr != null && minAddr == null) {
					minAddr = childMinAddr;
				}
				else if (childMinAddr != null && childMinAddr.compareTo(minAddr) < 0) {
					minAddr = childMinAddr;
				}
			}
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		return minAddr;

	}

	private Address findMaxAddress(ModuleDB module, Address addr) {
		Address maxAddr = addr;

		try {
			List<Record> list = module.getParentChildRecords();
			for (int i = 0; i < list.size(); i++) {
				Record rec = list.get(i);
				long childID = rec.getLongValue(TreeManager.CHILD_ID_COL);
				Address childMaxAddr = null;
				if (childID < 0) {
					FragmentDB frag = moduleMgr.getFragmentDB(-childID);
					if (!frag.isEmpty()) {
						childMaxAddr = frag.getMaxAddress();
					}
				}
				else {
					ModuleDB m = moduleMgr.getModuleDB(childID);
					childMaxAddr = findMaxAddress(m, addr);
				}
				if (childMaxAddr != null && maxAddr == null) {
					maxAddr = childMaxAddr;
				}
				else if (childMaxAddr != null && childMaxAddr.compareTo(maxAddr) > 0) {
					maxAddr = childMaxAddr;
				}
			}
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		return maxAddr;

	}

	private void updateChildCount() {
		checkIsValid();
		childCount = 0;
		try {
			long[] keys = adapter.getParentChildKeys(key, TreeManager.PARENT_ID_COL);
			childCount = keys.length;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
	}

	private class ParentChildRecordComparator implements Comparator<Record> {

		public int compare(Record r1, Record r2) {
			int index1 = r1.getIntValue(TreeManager.ORDER_COL);
			int index2 = r2.getIntValue(TreeManager.ORDER_COL);
			if (index1 < index2) {
				return -1;
			}
			if (index1 > index2) {
				return 1;
			}
			return 0;
		}

	}

	/**
	 * @see ghidra.program.model.listing.ProgramModule#getVersionTag()
	 */
	public Object getVersionTag() {
		return moduleMgr.getVersionTag();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.Module#getModificationNumber()
	 */
	public long getModificationNumber() {
		return moduleMgr.getModificationNumber();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.Module#getTreeID()
	 */
	public long getTreeID() {
		return moduleMgr.getTreeID();
	}

}
