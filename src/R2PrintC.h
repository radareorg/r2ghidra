/* r2ghidra - LGPL - Copyright 2019-2024 - pancake */

#ifndef R2GHIDRA_R2PRINTC_H
#define R2GHIDRA_R2PRINTC_H

#include <printc.hh>

// using namespace ghidra;

class R2PrintC : public ghidra::PrintC {
protected:
	void pushUnnamedLocation(const ghidra::Address &addr, const ghidra::Varnode *vn,const ghidra::PcodeOp *op) override;
	// void opCast(const PcodeOp *op) override;

public:
	explicit R2PrintC(ghidra::Architecture *g, const std::string &nm = "c-language");
	void setOptionNoCasts(bool nc);

};

class R2PrintCCapability : public ghidra::PrintLanguageCapability {
private:
	static R2PrintCCapability inst;
	R2PrintCCapability();

public:
	ghidra::PrintLanguage *buildLanguage(ghidra::Architecture *glb) override;
};

#endif //R2GHIDRA_R2PRINTC_H
