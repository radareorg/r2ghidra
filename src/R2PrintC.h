/* r2ghidra - LGPL - Copyright 2019-2024 - pancake */

#ifndef R2GHIDRA_R2PRINTC_H
#define R2GHIDRA_R2PRINTC_H

#include <printc.hh>

using namespace ghidra;

class R2PrintC : public PrintC {
protected:
	void pushUnnamedLocation(const Address &addr, const Varnode *vn,const PcodeOp *op) override;
	// void opCast(const PcodeOp *op) override;

public:
	explicit R2PrintC(Architecture *g, const string &nm = "c-language");
	void setOptionNoCasts(bool nc);

};

class R2PrintCCapability : public PrintLanguageCapability {
private:
	static R2PrintCCapability inst;
	R2PrintCCapability();

public:
	PrintLanguage *buildLanguage(Architecture *glb) override;
};

#endif //R2GHIDRA_R2PRINTC_H
