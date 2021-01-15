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
package ghidra.pcode.opbehavior;

import java.math.BigDecimal;
import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import ghidra.pcode.floatformat.FloatFormat;
import ghidra.pcode.floatformat.FloatFormatFactory;

public class OpBehaviorFloatAbsTest extends AbstractOpBehaviorTest {

	public OpBehaviorFloatAbsTest() {
		super();
	}

	@Test
	public void testEvaluateBinaryLong() {

		OpBehaviorFloatAbs op = new OpBehaviorFloatAbs();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		long a = ff.getEncoding(2.5);
		long result = op.evaluateUnary(8, 8, ff.opAbs(a));
		Assert.assertEquals(2.5, ff.getHostFloat(result), 0);

		a = ff.getEncoding(-2.5);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(2.5, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.POSITIVE_INFINITY);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NEGATIVE_INFINITY);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(Double.POSITIVE_INFINITY, ff.getHostFloat(result), 0);

		a = ff.getEncoding(Double.NaN);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(Double.NaN, ff.getHostFloat(result), 0);
	}

	@Test
	public void testEvaluateBinaryBigInteger() {

		OpBehaviorFloatAbs op = new OpBehaviorFloatAbs();

		FloatFormat ff = FloatFormatFactory.getFloatFormat(8);

		BigInteger a = ff.getEncoding(BigDecimal.valueOf(2.5d));
		BigInteger result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(BigDecimal.valueOf(2.5d), ff.getHostFloat(result));

		a = ff.getEncoding(BigDecimal.valueOf(-2.5d));
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(BigDecimal.valueOf(2.5d), ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_POSITIVE_INFINITY);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NEGATIVE_INFINITY);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(FloatFormat.BIG_POSITIVE_INFINITY, ff.getHostFloat(result));

		a = ff.getEncoding(FloatFormat.BIG_NaN);
		result = op.evaluateUnary(8, 8, a);
		Assert.assertEquals(FloatFormat.BIG_NaN, ff.getHostFloat(result));
	}

}
