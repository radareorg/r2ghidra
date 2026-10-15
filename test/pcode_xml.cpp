// SPDX-FileCopyrightText: 2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "PcodeXmlEncode.h"
#include <typeop.hh>
#include <translate.hh>
#include <iostream>
#include <sstream>
#include <stdexcept>

using namespace ghidra;

class TestSpaces : public AddrSpaceManager {
public:
	TestSpaces() {
		insertSpace(new ConstantSpace(this, nullptr));
		insertSpace(new AddrSpace(this, nullptr, IPTR_PROCESSOR, "ram", false, 8, 1, 1, 0, 1, 1));
	}
};

static void require(bool condition, const char *message) {
	if (!condition) {
		throw std::runtime_error(message);
	}
}

static SeqNum decodeSequence(const std::string &xml, TestSpaces &spaces) {
	std::istringstream input(xml);
	XmlDecode decoder(&spaces);
	decoder.ingestStream(input);
	decoder.openElement(ELEM_OP);
	return SeqNum::decode(decoder);
}

static void checkOperation(PcodeOpBank &bank, PcodeOp *operation, TestSpaces &spaces) {
	std::ostringstream output;
	PcodeXmlEncode encoder(output, bank);
	operation->encode(encoder);
	const std::string expected = operation->isDead() ? "is_dead=\"true\"" : "is_dead=\"false\"";
	require(output.str().find(expected) != std::string::npos, "Export differs from native dead state");
	require(output.str().find("is_dead=") == output.str().rfind("is_dead="), "Duplicate dead-state attribute");
	std::ostringstream original;
	XmlEncode originalEncoder(original);
	operation->encode(originalEncoder);
	std::string unchanged = output.str();
	unchanged.erase(unchanged.find(expected) - 1, expected.size() + 1);
	require(unchanged == original.str(), "Other native XML content changed");
	require(decodeSequence(output.str(), spaces) == decodeSequence(original.str(), spaces),
		"Native sequence decoder changed after adding metadata");
}

int main() {
	try {
		AttributeId::initialize();
		ElementId::initialize();
		TestSpaces spaces;
		TypeOpCopy copy(nullptr);
		PcodeOpBank bank;
		const Address address(spaces.getSpaceByName("ram"), 0x20000000000001ULL);
		auto *live = bank.create(0, SeqNum(address, 11));
		auto *dead = bank.create(0, SeqNum(address, 12));
		auto *other = bank.create(0, SeqNum(address + 4, 11));
		for (auto *operation : {live, dead, other}) {
			bank.changeOpcode(operation, &copy);
		}
		bank.markAlive(live);
		checkOperation(bank, live, spaces);
		checkOperation(bank, dead, spaces);
		checkOperation(bank, other, spaces);
		bank.markDead(live);
		checkOperation(bank, live, spaces);
		bank.markAlive(dead);
		checkOperation(bank, dead, spaces);

		std::ostringstream output;
		PcodeXmlEncode encoder(output, bank);
		SeqNum(address, 99).encode(encoder);
		require(output.str().find("is_dead=") == std::string::npos, "Non-operation sequence was annotated");
		bool rejected = false;
		try {
			PcodeOpBank foreign;
			auto *absent = foreign.create(0, SeqNum(address, 99));
			foreign.changeOpcode(absent, &copy);
			absent->encode(encoder);
		} catch (const LowlevelError &) {
			rejected = true;
		}
		require(rejected, "Missing source identity was given an invented dead state");
		std::cout << "Native p-code XML state, identity and legacy decoding checks passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
	} catch (const LowlevelError &error) {
		std::cerr << error.explain << '\n';
	}
	return 1;
}
