/* r2ghidra - LGPL - Copyright 2019-2023 - thestr4ng3r */

#ifndef R2GHIDRA_R2ARCHITECTURE_H
#define R2GHIDRA_R2ARCHITECTURE_H

#include "architecture.hh"
#include "sleigh_arch.hh"

#include "RCoreMutex.h"

// using namespace ghidra;

class R2TypeFactory;
typedef struct r_core_t RCore;

class R2Architecture : public ghidra::SleighArchitecture {
private:
	RCoreMutex coreMutex;

	R2TypeFactory *r2TypeFactory_ = nullptr;
	std::map<std::string, ghidra::VarnodeData> registers;
	std::vector<std::string> warnings;

	bool rawptr = false;

	void loadRegisters(const ghidra::Translate *translate);

public:
	explicit R2Architecture(RCore *core, const std::string &sleigh_id);

	RCoreMutex *getCore() { return &coreMutex; }

	R2TypeFactory *getTypeFactory() const { return r2TypeFactory_; }

	ghidra::ProtoModel *protoModelFromR2CC(const char *cc);
	ghidra::Address registerAddressFromR2Reg(const char *regname);

	void addWarning(const std::string &warning)	{ warnings.push_back(warning); }
	const std::vector<std::string> getWarnings() const { return warnings; }
	ghidra::ContextDatabase *getContextDatabase();

	void setRawPtr(bool rawptr) { this->rawptr = rawptr; }

protected:
	ghidra::Translate *buildTranslator(ghidra::DocumentStorage &store) override;
	void buildLoader(ghidra::DocumentStorage &store) override;
	ghidra::Scope *buildDatabase(ghidra::DocumentStorage &store) override;
	void buildTypegrp(ghidra::DocumentStorage &store) override;
	void buildCoreTypes(ghidra::DocumentStorage &store) override;
	void buildCommentDB(ghidra::DocumentStorage &store) override;
	void postSpecFile() override;
	void buildAction(ghidra::DocumentStorage &store) override;
};

#endif //R2GHIDRA_R2ARCHITECTURE_H
