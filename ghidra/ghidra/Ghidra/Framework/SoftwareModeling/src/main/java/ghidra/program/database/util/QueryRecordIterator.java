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
/*
 *
 */
package ghidra.program.database.util;

import ghidra.util.Msg;
import ghidra.util.exception.ClosedException;

import java.io.IOException;

import db.Record;
import db.RecordIterator;

/**
 * Iterator that only returns records from another iterator that match the given query.
 */
public class QueryRecordIterator implements RecordIterator {

	private RecordIterator iter;
	private Query query;
	private Record record;
	private boolean forward;

	/**
	 * Constructs a new QueryRecordIterator that filters the given record iterator with
	 * the given Query.
	 * @param iter the record iterator to filter.
	 * @param query the query used to filter.
	 */
	public QueryRecordIterator(RecordIterator iter, Query query) {
		this(iter, query, true);
	}

	/**
	 * Constructor
	 * @param iter record iterator
	 * @param query query needed to match the record
	 * @param forward true means iterate in the forward direction
	 */
	public QueryRecordIterator(RecordIterator iter, Query query, boolean forward) {
		this.iter = iter;
		this.query = query;
		this.forward = forward;
	}

	/** 
	 * @see db.RecordIterator#hasNext()
	 */
	public boolean hasNext() throws IOException {
		if (record == null) {
			if (forward) {
				findNext();
			}
			else {
				findPrevious();
			}
		}
		return record != null;
	}

	/**
	 * @see db.RecordIterator#next()
	 */
	public Record next() throws IOException {
		if (hasNext()) {
			Record rec = record;
			record = null;
			return rec;
		}
		return null;
	}

	/**
	 * @see db.RecordIterator#hasPrevious()
	 */
	public boolean hasPrevious() throws IOException {
		if (record == null) {
			findPrevious();
		}
		return record != null;
	}

	/**
	 * @see db.RecordIterator#previous()
	 */
	public Record previous() throws IOException {
		if (hasPrevious()) {
			Record rec = record;
			record = null;
			return rec;
		}
		return null;
	}

	/**
	 * @see db.RecordIterator#delete()
	 */
	public boolean delete() throws IOException {
		return iter.delete();
	}

	private void findNext() {
		try {
			while (iter.hasNext()) {
				Record rec = iter.next();
				if (query.matches(rec)) {
					record = rec;
					return;
				}
			}
		}
		catch (ClosedException e) {
			// just make it look like the iterator is done 
		}
		catch (IOException e) {
			Msg.showError(this, null, null, null, e);
		}
	}

	private void findPrevious() {
		try {
			while (iter.hasPrevious()) {
				Record rec = iter.previous();
				if (query.matches(rec)) {
					record = rec;
					return;
				}
			}
		}
		catch (ClosedException e) {
			// just make it look like the iterator is done 
		}
		catch (IOException e) {
			Msg.showError(this, null, null, null, e);
		}
	}
}
