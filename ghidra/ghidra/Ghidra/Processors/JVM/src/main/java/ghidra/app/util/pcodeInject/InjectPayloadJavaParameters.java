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
package ghidra.app.util.pcodeInject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.javaclass.format.*;
import ghidra.javaclass.format.constantpool.ConstantPoolUtf8Info;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

public class InjectPayloadJavaParameters implements InjectPayload {

	private InjectParameter[] noParams;
	private boolean analysisStateRecoverable;
	private AddressSpace constantSpace;
	private int paramSpaceID;
	private int lvaID;
	private Varnode temp4;
	private Varnode temp8;
	private Varnode zero;
	private Varnode four;
	private Varnode eight;
	private Varnode LVA;

	public InjectPayloadJavaParameters(SleighLanguage language, long uniqBase) {
		noParams = new InjectParameter[0];
		analysisStateRecoverable = true;
		constantSpace = language.getAddressFactory().getConstantSpace();
		AddressSpace uniqueSpace = language.getAddressFactory().getUniqueSpace();
		Address temp4Address = uniqueSpace.getAddress(uniqBase);
		Address temp8Address = uniqueSpace.getAddress(uniqBase + 0x10);
		AddressSpace paramSpace = language.getAddressFactory().getAddressSpace("parameterSpace");
		paramSpaceID = paramSpace.getSpaceID();
		AddressSpace lva = language.getAddressFactory().getAddressSpace("localVariableArray");
		lvaID = lva.getSpaceID();
		//create temp storage locations
		temp4 = new Varnode(temp4Address, 4);
		temp8 = new Varnode(temp8Address, 8);
		//create varnodes for incrementing pointer by 4 or 8 bytes
		zero = new Varnode(constantSpace.getAddress(0), 4);
		four = new Varnode(constantSpace.getAddress(4), 4);
		eight = new Varnode(constantSpace.getAddress(8), 4);
		Address LVAregAddress = language.getRegister("LVA").getAddress();
		LVA = new Varnode(LVAregAddress, 4);
	}

	@Override
	public String getName() {
		return "javaparameters";
	}

	@Override
	public int getType() {
		return CALLMECHANISM_TYPE;
	}

	@Override
	public String getSource() {
		return "javaparameters";
	}

	@Override
	public int getParamShift() {
		return 0;
	}

	@Override
	public InjectParameter[] getInput() {
		return noParams;
	}

	@Override
	public InjectParameter[] getOutput() {
		return noParams;
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit) {
		//not used
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		if (!analysisStateRecoverable) {
			return new PcodeOp[0];
		}
		ClassFileAnalysisState analysisState;
		try {
			analysisState = ClassFileAnalysisState.getState(program);
		}
		catch (IOException e) {
			Msg.error(this, e.getMessage(), e);
			analysisStateRecoverable = false;
			return new PcodeOp[0];
		}
		ClassFileJava classFile = analysisState.getClassFile();
		MethodInfoJava methodInfo = analysisState.getMethodInfo(con.baseAddr);
		if (methodInfo == null){
			return new PcodeOp[0];
		}
		int descriptorIndex = methodInfo.getDescriptorIndex();
		ConstantPoolUtf8Info descriptorInfo = (ConstantPoolUtf8Info)(classFile.getConstantPool()[descriptorIndex]);
		String descriptor = descriptorInfo.getString();
		List<JavaComputationalCategory> paramCategories = new ArrayList<>();
		if (!methodInfo.isStatic()){
			paramCategories.add(JavaComputationalCategory.CAT_1);//for the this pointer
		}
		paramCategories.addAll(DescriptorDecoder.getParameterCategories(descriptor));
		int numOps = paramCategories.size();

		if (paramCategories.size() == 0){
			//no this pointer, no parameters: nothing to do
			return new PcodeOp[0];
		}

		PcodeOp[] resOps = new PcodeOp[1 + 3*numOps];
		int seqNum = 0;

		//initialize LVA to contain 0
		PcodeOp copy = new PcodeOp(con.baseAddr,seqNum, PcodeOp.COPY);
		copy.setInput(zero, 0);
		copy.setOutput(LVA);
		resOps[seqNum++] = copy;

		Varnode tempLocation = null;
		Varnode increment = null;

		for (JavaComputationalCategory cat : paramCategories){
			if (cat.equals(JavaComputationalCategory.CAT_1)){
				tempLocation = temp4;
				increment = four;
			}
			else {
				tempLocation = temp8;
				increment = eight;
			}
			//copy value from parameterSpace to temporary
			PcodeOp load = new PcodeOp(con.baseAddr, seqNum, PcodeOp.LOAD);
			load.setInput(new Varnode(constantSpace.getAddress(paramSpaceID), 4), 0);
			load.setInput(LVA, 1);
			load.setOutput(tempLocation);
			resOps[seqNum++] = load;
			//copy temporary to LVA
			PcodeOp store = new PcodeOp(con.baseAddr, seqNum, PcodeOp.STORE);
			store.setInput(new Varnode(constantSpace.getAddress(lvaID), 4), 0);
			store.setInput(LVA,1);
			store.setInput(tempLocation, 2);
			resOps[seqNum++] = store;			
			//increment LVA reg 
			PcodeOp add = new PcodeOp(con.baseAddr, seqNum, PcodeOp.INT_ADD);
			add.setInput(LVA, 0);
			add.setInput(increment, 1);
			add.setOutput(LVA);
			resOps[seqNum++] = add;	
		}	
		return resOps;
	}

	@Override
	public boolean isFallThru() {
		return true;
	}
}
