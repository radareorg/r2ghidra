// SPDX-FileCopyrightText: 2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R2GHIDRA_PCODE_XML_ENCODE_H
#define R2GHIDRA_PCODE_XML_ENCODE_H

#include <op.hh>
#include <translate.hh>

// OperationSource owns findOp(SeqNum), as provided by Funcdata and PcodeOpBank.
template <typename OperationSource>
class PcodeXmlEncode : public ghidra::XmlEncode {
private:
	OperationSource &operations;
	std::ostream &output;
	bool inOperation = false;
	bool inSequence = false;
	const ghidra::AddrSpace *sequenceSpace = nullptr;
	ghidra::uintb sequenceOffset = 0;
	bool hasOffset = false;

public:
	PcodeXmlEncode(std::ostream &stream, OperationSource &source)
		: ghidra::XmlEncode(stream), operations(source), output(stream) {}

	void openElement(const ghidra::ElementId &element) override {
		ghidra::XmlEncode::openElement(element);
		if (element == ghidra::ELEM_OP) {
			inOperation = true;
		} else if (inOperation && element == ghidra::ELEM_SEQNUM) {
			inSequence = true;
			sequenceSpace = nullptr;
			hasOffset = false;
		}
	}

	void closeElement(const ghidra::ElementId &element) override {
		ghidra::XmlEncode::closeElement(element);
		if (element == ghidra::ELEM_SEQNUM) {
			inSequence = false;
		} else if (element == ghidra::ELEM_OP) {
			inOperation = false;
		}
	}

	void writeSpace(const ghidra::AttributeId &attribute, const ghidra::AddrSpace *space) override {
		ghidra::XmlEncode::writeSpace(attribute, space);
		if (inSequence && attribute == ghidra::ATTRIB_SPACE) {
			sequenceSpace = space;
		}
	}

	void writeUnsignedInteger(const ghidra::AttributeId &attribute, ghidra::uintb value) override {
		ghidra::XmlEncode::writeUnsignedInteger(attribute, value);
		if (!inSequence) {
			return;
		}
		if (attribute == ghidra::ATTRIB_OFFSET) {
			sequenceOffset = value;
			hasOffset = true;
		} else if (attribute == ghidra::ATTRIB_UNIQ) {
			if (!sequenceSpace || !hasOffset || static_cast<ghidra::uintm>(value) != value) {
				throw ghidra::LowlevelError("Invalid p-code operation sequence in XML export");
			}
			const ghidra::Address address(const_cast<ghidra::AddrSpace *>(sequenceSpace), sequenceOffset);
			const auto *operation = operations.findOp(ghidra::SeqNum(address, value));
			if (!operation) {
				throw ghidra::LowlevelError("P-code operation sequence is absent from XML export source");
			}
			output << " is_dead=\"" << (operation->isDead() ? "true" : "false") << "\"";
		}
	}
};

#endif
