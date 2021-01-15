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
package pdb;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import docking.DockingWindowManager;
import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.app.plugin.core.analysis.*;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.bin.format.pdb.PdbException;
import ghidra.app.util.bin.format.pdb.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.*;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

class LoadPdbTask extends Task {
	private File pdbFile;
	private DataTypeManagerService service;
	private final Program program;
	private final boolean useMsDiaParser;
	private final PdbApplicatorRestrictions restrictions; // PDB Universal Parser only

	LoadPdbTask(Program program, File pdbFile, boolean useMsDiaParser,
			PdbApplicatorRestrictions restrictions, DataTypeManagerService service) {
		super("Loading PDB...", true, false, false);
		this.program = program;
		this.pdbFile = pdbFile;
		this.useMsDiaParser = useMsDiaParser;
		this.restrictions = restrictions;
		this.service = service;
	}

	@Override
	public void run(final TaskMonitor monitor) {
		final MessageLog log = new MessageLog();

		AnalysisWorker worker = new AnalysisWorker() {

			@Override
			public String getWorkerName() {
				return "Load PDB";
			}

			@Override
			public boolean analysisWorkerCallback(Program currentProgram, Object workerContext,
					TaskMonitor currentMonitor) throws CancelledException {

				try {
					if (useMsDiaParser) {
						if (!parseWithMsDiaParser(log, monitor)) {
							return false;
						}
					}
					else if (!parseWithNewParser(log, monitor)) {
						return false;
					}
					analyzeSymbols(currentMonitor, log);
				}
				catch (IOException e) {
					log.appendMsg("PDB IO Error: " + e.getMessage());
				}
				return false;
			}
		};



		try {
			AutoAnalysisManager.getAnalysisManager(program)
					.scheduleWorker(worker, null, true,
						monitor);
			if (log.hasMessages()) {
				MultiLineMessageDialog dialog = new MultiLineMessageDialog("Load PDB File",
					"There were warnings/errors loading the PDB file.", log.toString(),
					MultiLineMessageDialog.WARNING_MESSAGE, false);
				DockingWindowManager.showDialog(null, dialog);
			}
		}
		catch (InterruptedException | CancelledException e1) {
			// ignore
		}
		catch (InvocationTargetException e) {
			String message;

			Throwable t = e.getCause();

			if (t == null) {
				message = "Unknown cause";
			}
			else {
				message = t.getMessage();

				if (message == null) {
					message = t.toString();
				}
			}

			message = "Error processing PDB file:  " + pdbFile + ".\n" + message;

			Msg.showError(getClass(), null, "Load PDB Failed", message, t);
		}

	}

	private boolean parseWithMsDiaParser(MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		PdbParser parser = new PdbParser(pdbFile, program, service, true, monitor);
		try {
			parser.parse();
			parser.openDataTypeArchives();
			parser.applyTo(log);
			return true;
		}
		catch (PdbException | DuplicateIdException e) {
			log.appendMsg("PDB Error: " + e.getMessage());
		}
		return false;
	}

	private boolean parseWithNewParser(MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {

		PdbReaderOptions pdbReaderOptions = new PdbReaderOptions(); // use defaults

		PdbApplicatorOptions pdbApplicatorOptions = new PdbApplicatorOptions();

		pdbApplicatorOptions.setRestrictions(restrictions);

		try (AbstractPdb pdb =
			ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser.parse(pdbFile.getAbsolutePath(),
				pdbReaderOptions, monitor)) {
			monitor.setMessage("PDB: Parsing " + pdbFile + "...");
			pdb.deserialize(monitor);
			PdbApplicator applicator = new PdbApplicator(pdbFile.getAbsolutePath(), pdb);
			applicator.applyTo(program, program.getDataTypeManager(), program.getImageBase(),
				pdbApplicatorOptions, monitor, log);
			return true;
		}
		catch (ghidra.app.util.bin.format.pdb2.pdbreader.PdbException e) {
			log.appendMsg("PDB Error: " + e.getMessage());
		}
		return false;
	}
	
	private void analyzeSymbols(TaskMonitor monitor, MessageLog log) {

		MicrosoftDemanglerAnalyzer demanglerAnalyzer = new MicrosoftDemanglerAnalyzer();
		String analyzerName = demanglerAnalyzer.getName();

		Options analysisProperties = program.getOptions(Program.ANALYSIS_PROPERTIES);
		String defaultValueAsString = analysisProperties.getValueAsString(analyzerName);
		boolean doDemangle = true;
		if (defaultValueAsString != null) {
			doDemangle = Boolean.parseBoolean(defaultValueAsString);
		}

		if (doDemangle) {
			AddressSetView addrs = program.getMemory();
			monitor.initialize(addrs.getNumAddresses());
			try {
				demanglerAnalyzer.added(program, addrs, monitor, log);
			}
			catch (CancelledException e) {
				// ignore cancel
			}
		}
	}
}
