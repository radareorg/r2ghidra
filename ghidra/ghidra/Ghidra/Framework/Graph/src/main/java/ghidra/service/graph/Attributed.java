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
package ghidra.service.graph;

import java.util.*;

public class Attributed {

	/**
	 * the {@link HashMap} to contain attribute mappings
	 */
	private Map<String, String> attributes = new HashMap<>();

	/**
	 * Returns an unmodifiable view of the attribute map
	 * @return an unmodifiable view of the attribute map
	 */

	public Map<String, String> getAttributeMap() {
		return Collections.unmodifiableMap(attributes);
	}

	/**
	 * Sets the attribute with the given key and value
	 *
	 * @param key attribute key
	 * @param value attribute value
	 * @return the previous value of the attribute
	 */
	public String setAttribute(String key, String value) {
		return attributes.put(key, value);
	}

	/**
	 * gets the value of the given attribute name
	 *
	 * @param key attribute name
	 * @return the mapped value for the supplied key
	 */
	public String getAttribute(String key) {
		return attributes.get(key);
	}

	/**
	 * Removes the attribute with the given key
	 *
	 * @param key attribute key
	 * @return the value of the removed attribute
	 */
	public String removeAttribute(String key) {
		return attributes.remove(key);
	}

	/**
	 * Returns true if there is an attribute with that name
	 *
	 * @param key attribute key
	 * @return true if there is an attribute with that name
	 */
	public boolean hasAttribute(String key) {
		return attributes.containsKey(key);
	}

	/**
	 * Returns the number of attributes defined
	 * 
	 * @return the number of attributes defined
	 */
	public int size() {
		return attributes.size();
	}

	/**
	 * Return true if there are no attributes
	 *
	 * @return true if there are no mapped attributes
	 */
	public boolean isEmpty() {
		return attributes.isEmpty();
	}

	/**
	 * Adds all the key/value pairs from the given map as attributes
	 *
	 * @param map a map of key/values to add as attributes
	 */
	public void putAttributes(Map<String, String> map) {
		attributes.putAll(map);
	}

	/**
	 * removes all key/value mappings
	 */
	public void clear() {
		attributes.clear();
	}

	/**
	 * Returns the keys for the attributes
	 *
	 * @return the keys for the attributes
	 */
	public Set<String> keys() {
		return attributes.keySet();
	}

	/**
	 * Returns the attribute values
	 *
	 * @return the attribute values
	 */
	public Collection<String> values() {
		return attributes.values();
	}

	/**
	 * Returns a {@link Set} containing the key/value entry associations
	 *
	 * @return a {@link Set} containing the key/value entry associations
	 */
	public Set<Map.Entry<String, String>> entrySet() {
		return attributes.entrySet();
	}

}
