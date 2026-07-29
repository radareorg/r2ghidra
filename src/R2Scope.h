// SPDX-FileCopyrightText: 2019-2021 thestr4ng3r, pancake
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R2GHIDRA_R2SCOPE_H
#define R2GHIDRA_R2SCOPE_H

#include <database.hh>
#include <memory>

#include <r_types.h>

// Windows defines LoadImage to LoadImageA
#ifdef LoadImage
#undef LoadImage
#endif

using namespace ghidra;

class R2Architecture;
typedef struct r_anal_function_t RAnalFunction;
typedef struct r_flag_item_t RFlagItem;

class R2Scope : public Scope {
private:
	R2Architecture *arch;
	ScopeInternal *cache;
	std::unique_ptr<uint8> next_id;

	uint8 makeId() const { return (*next_id)++; }

	FunctionSymbol *registerFunction(RAnalFunction *fcn) const;
	FunctionSymbol *registerFunctionFlag(RFlagItem *flag) const;
	Symbol *registerFlag(RFlagItem *flag) const;
	Symbol *registerGlobalVar(RFlagItem *glob, const char *type_str) const;
	Symbol *queryR2Absolute(ut64 addr, bool contain) const;
	Symbol *queryR2(const Address &addr, bool contain) const;
	LabSymbol *queryR2FunctionLabel(const Address &addr) const;

protected:
	// TODO? void addRange(AddrSpace *spc,uintb first,uintb last) override;
	void removeRange(AddrSpace *spc,uintb first,uintb last) override				{ throw LowlevelError("remove_range should not be performed on radare2 scope"); }
	void addSymbolInternal(Symbol *sym) override									{ throw LowlevelError("addSymbolInternal unimplemented"); }
	void addMapInternal(Symbol *sym, MapEntry *entry) override						{ throw LowlevelError("addMapInternal unimplemented"); }
	void addDynamicMapInternal(Symbol *sym, DynamicEntry *entry) override			{ throw LowlevelError("addMap unimplemented"); }

public:
	explicit R2Scope(R2Architecture *arch);
	~R2Scope() override;

	Scope *buildSubScope(uint8 id, const string &nm) override;
	void clear(void) override										{ cache->clear(); }
	MapEntry *addSymbol(const string &name, Datatype *ct, const Address &addr, const Address &usepoint) override	{ return cache->addSymbol(name, ct, addr, usepoint); }
	string buildVariableName(const Address &addr, const Address &pc, Datatype *ct,int4 &index,uint4 flags) const override { return cache->buildVariableName(addr,pc,ct,index,flags); }
	string buildUndefinedName(void) const override					{ return cache->buildUndefinedName(); }
	void setAttribute(Symbol *sym,uint4 attr) override				{ cache->setAttribute(sym,attr); }
	void clearAttribute(Symbol *sym,uint4 attr) override			{ cache->clearAttribute(sym,attr); }
	void setDisplayFormat(Symbol *sym,uint4 attr) override			{ cache->setDisplayFormat(sym,attr); }
	void adjustCaches(void) override { cache->adjustCaches(); }

	MapEntry *findAddr(const Address &addr,const Address &usepoint) const override;
	MapEntry *findContainer(const Address &addr,int4 size, const Address &usepoint) const override;
	MapEntry *findClosestFit(const Address &addr,int4 size, const Address &usepoint) const override { throw LowlevelError("findClosestFit unimplemented"); }
	Funcdata *findFunction(const Address &addr) const override;
	ExternRefSymbol *findExternalRef(const Address &addr) const override;
	LabSymbol *findCodeLabel(const Address &addr) const override;
	bool isNameUsed(const string &name, const Scope *op2) const override { throw LowlevelError("isNameUsed unimplemented"); }
	Funcdata *resolveExternalRefFunction(ExternRefSymbol *sym) const override;

	MapEntry *findOverlap(const Address &addr,int4 size) const override { throw LowlevelError("findOverlap unimplemented"); }
	SymbolEntry *findBefore(const Address &addr) const				{ throw LowlevelError("findBefore unimplemented"); }
	SymbolEntry *findAfter(const Address &addr) const				{ throw LowlevelError("findAfter unimplemented"); }
	void findByName(const string &name,vector<Symbol *> &res) const	override { throw LowlevelError("findByName unimplemented"); }
	MapIterator begin() const override								{ throw LowlevelError("begin unimplemented"); }
	MapIterator end() const override								{ throw LowlevelError("end unimplemented"); }
	list<DynamicEntry *>::const_iterator beginDynamic() const override	{ throw LowlevelError("beginDynamic unimplemented"); }
	list<DynamicEntry *>::const_iterator endDynamic() const override	{ throw LowlevelError("endDynamic unimplemented"); }
	list<DynamicEntry *>::iterator beginDynamic() override				{ throw LowlevelError("beginDynamic unimplemented"); }
	list<DynamicEntry *>::iterator endDynamic() override				{ throw LowlevelError("endDynamic unimplemented"); }
	void clearCategory(int4 cat) override							{ throw LowlevelError("clearCategory unimplemented"); }
	void clearUnlockedCategory(int4 cat) override					{ throw LowlevelError("clearUnlockedCategory unimplemented"); }
	void clearUnlocked() override									{ throw LowlevelError("clearUnlocked unimplemented"); }
	void restrictScope(Funcdata *f) override						{ throw LowlevelError("restrictScope unimplemented"); }
	void removeSymbolMappings(Symbol *symbol) override				{ throw LowlevelError("removeSymbolMappings unimplemented"); }
	void removeSymbol(Symbol *symbol) override						{ throw LowlevelError("removeSymbol unimplemented"); }
	void renameSymbol(Symbol *sym,const string &newname) override	{ throw LowlevelError("renameSymbol unimplemented"); }
	void retypeSymbol(Symbol *sym,Datatype *ct) override			{ throw LowlevelError("retypeSymbol unimplemented"); }
	string makeNameUnique(const string &nm) const override			{ throw LowlevelError("makeNameUnique unimplemented"); }
	void encode(Encoder &encoder) const override { cache->encode(encoder); }
	void decode(Decoder &decoder) override { throw LowlevelError("not implemented"); }
	void printEntries(ostream &s) const override					{ throw LowlevelError("printEntries unimplemented"); }
	int4 getCategorySize(int4 cat) const override					{ throw LowlevelError("getCategorySize unimplemented"); }
	Symbol *getCategorySymbol(int4 cat,int4 ind) const override		{ throw LowlevelError("getCategorySymbol unimplemented"); }
	void setCategory(Symbol *sym,int4 cat,int4 ind) override		{ throw LowlevelError("setCategory unimplemented"); }
};

#endif //R2GHIDRA_R2SCOPE_H
