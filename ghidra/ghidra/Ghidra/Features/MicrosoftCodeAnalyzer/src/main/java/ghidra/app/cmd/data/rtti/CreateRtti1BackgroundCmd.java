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
package ghidra.app.cmd.data.rtti;

import ghidra.app.cmd.data.*;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;

/**
 * This command will create an RTTI1 data type. 
 * If there are any existing instructions in the area to be made into data, the command will fail.
 * Any data in the area will be replaced with the new dataType.
 */
public class CreateRtti1BackgroundCmd extends AbstractCreateDataBackgroundCmd<Rtti1Model> {

	private static final String RTTI_1_NAME = "RTTI Base Class Descriptor";

	/**
	 * Constructs a command for applying an RTTI1 dataType at an address.
	 * @param address the address where the data should be created using the data type.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateRtti1BackgroundCmd(Address address, DataValidationOptions validationOptions,
			DataApplyOptions applyOptions) {
		super(Rtti1Model.DATA_TYPE_NAME, address, 1, validationOptions, applyOptions);
	}

	/**
	 * Constructs a command for applying an RTTI1 dataType at the address indicated by the 
	 * model.
	 * @param rtti1Model the model for the data type
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	CreateRtti1BackgroundCmd(Rtti1Model rtti1Model, DataApplyOptions applyOptions) {
		super(rtti1Model, applyOptions);
	}

	@Override
	protected Rtti1Model createModel(Program program) {
		if (model == null || program != model.getProgram()) {
			model = new Rtti1Model(program, getDataAddress(), validationOptions);
		}
		return model;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {

		return createRtti0() | createRtti3();
	}

	private boolean createRtti0() throws CancelledException {

		monitor.checkCanceled();

		CreateTypeDescriptorBackgroundCmd cmd =
			new CreateTypeDescriptorBackgroundCmd(model.getRtti0Model(), applyOptions);
		return cmd.applyTo(model.getProgram(), monitor);
	}

	private boolean createRtti3() throws CancelledException {

		monitor.checkCanceled();

		CreateRtti3BackgroundCmd cmd =
			new CreateRtti3BackgroundCmd(model.getRtti3Model(), applyOptions);
		return cmd.applyTo(model.getProgram(), monitor);
	}

	@Override
	protected boolean createMarkup() throws CancelledException {

		monitor.checkCanceled();

		Program program = model.getProgram();
		TypeDescriptorModel rtti0Model = model.getRtti0Model();

		monitor.checkCanceled();

		if (rtti0Model != null) {

			String suffix = "";
			try {
				suffix = " at " + getPMDAttrList(program);
			}
			catch (InvalidDataTypeException e) {
				// Couldn't get pmd and attributes so leave it off and simply log the error.
				String message =
					"Unable to get PMD and attributes for RTTI1 at " + getDataAddress() + ".";
				handleError(message);
			}

			// Plate Comment
			EHDataTypeUtilities.createPlateCommentIfNeeded(program,
				RttiUtil.getDescriptorTypeNamespace(rtti0Model) + Namespace.DELIMITER, RTTI_1_NAME,
				suffix, getDataAddress(), applyOptions);

			monitor.checkCanceled();

			// Label
			if (applyOptions.shouldCreateLabel()) {
				String rtti1Suffix = RTTI_1_NAME + suffix;
				rtti1Suffix = SymbolUtilities.replaceInvalidChars(rtti1Suffix, true);
				RttiUtil.createSymbolFromDemangledType(program, getDataAddress(), rtti0Model,
					rtti1Suffix);
			}

		}

		return true;
	}

	private String getPMDAttrList(Program program) throws InvalidDataTypeException {
		int mDisp = model.getMDisp();
		int pDisp = model.getPDisp();
		int vDisp = model.getVDisp();
		int attributes = model.getAttributes();
		return "(" + mDisp + "," + pDisp + "," + vDisp + "," + attributes + ")";
	}

}
