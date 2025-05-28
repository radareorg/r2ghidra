/* r2ghidra - LGPL - Copyright 2019-2021 - thestr4ng3r, pancake */

#ifndef R2GHIDRA_R2SCOPE_H
#define R2GHIDRA_R2SCOPE_H

#include <database.hh>
#include <memory>

#include <r_types.h>

// Windows defines LoadImage to LoadImageA
#ifdef LoadImage
#undef LoadImage
#endif

// using namespace ghidra;

class R2Architecture;
typedef struct r_anal_function_t RAnalFunction;
typedef struct r_flag_item_t RFlagItem;

class R2Scope : public ghidra::Scope {
private:
	R2Architecture *arch;
	ghidra::ScopeInternal *cache;
	std::unique_ptr<ghidra::uint8> next_id;

	ghidra::uint8 makeId() const { return (*next_id)++; }

	ghidra::FunctionSymbol *registerFunction(RAnalFunction *fcn) const;
	ghidra::Symbol *registerFlag(RFlagItem *flag) const;
	ghidra::Symbol *queryR2Absolute(ut64 addr, bool contain) const;
	ghidra::Symbol *queryR2(const ghidra::Address &addr, bool contain) const;
	ghidra::LabSymbol *queryR2FunctionLabel(const ghidra::Address &addr) const;

protected:
	// TODO? void addRange(AddrSpace *spc,uintb first,uintb last) override;
	void removeRange(ghidra::AddrSpace *spc,ghidra::uintb first,ghidra::uintb last) override				{ throw ghidra::LowlevelError("remove_range should not be performed on radare2 scope"); }
	void addSymbolInternal(ghidra::Symbol *sym) override									{ throw ghidra::LowlevelError("addSymbolInternal unimplemented"); }
	ghidra::SymbolEntry *addMapInternal(ghidra::Symbol *sym, ghidra::uint4 exfl, const ghidra::Address &addr, ghidra::int4 off, ghidra::int4 sz, const ghidra::RangeList &uselim) override { throw ghidra::LowlevelError("addMapInternal unimplemented"); }
	ghidra::SymbolEntry *addDynamicMapInternal(ghidra::Symbol *sym, ghidra::uint4 exfl, ghidra::uint8 hash, ghidra::int4 off, ghidra::int4 sz, const ghidra::RangeList &uselim) override { throw ghidra::LowlevelError("addMap unimplemented"); }

public:
	explicit R2Scope(R2Architecture *arch);
	~R2Scope() override;

	Scope *buildSubScope(ghidra::uint8 id, const std::string &nm) override;
	void clear(void) override										{ cache->clear(); }
	ghidra::SymbolEntry *addSymbol(const std::string &name, ghidra::Datatype *ct, const ghidra::Address &addr, const ghidra::Address &usepoint) override	{ return cache->addSymbol(name, ct, addr, usepoint); }
	std::string buildVariableName(const ghidra::Address &addr, const ghidra::Address &pc, ghidra::Datatype *ct,ghidra::int4 &index,ghidra::uint4 flags) const override { return cache->buildVariableName(addr,pc,ct,index,flags); }
	std::string buildUndefinedName(void) const override					{ return cache->buildUndefinedName(); }
	void setAttribute(ghidra::Symbol *sym,ghidra::uint4 attr) override				{ cache->setAttribute(sym,attr); }
	void clearAttribute(ghidra::Symbol *sym,ghidra::uint4 attr) override			{ cache->clearAttribute(sym,attr); }
	void setDisplayFormat(ghidra::Symbol *sym,ghidra::uint4 attr) override			{ cache->setDisplayFormat(sym,attr); }
	void adjustCaches(void) override { cache->adjustCaches(); }

	ghidra::SymbolEntry *findAddr(const ghidra::Address &addr,const ghidra::Address &usepoint) const override;
	ghidra::SymbolEntry *findContainer(const ghidra::Address &addr,ghidra::int4 size, const ghidra::Address &usepoint) const override;
	ghidra::SymbolEntry *findClosestFit(const ghidra::Address &addr,ghidra::int4 size, const ghidra::Address &usepoint) const override { throw ghidra::LowlevelError("findClosestFit unimplemented"); }
	ghidra::Funcdata *findFunction(const ghidra::Address &addr) const override;
	ghidra::ExternRefSymbol *findExternalRef(const ghidra::Address &addr) const override;
	ghidra::LabSymbol *findCodeLabel(const ghidra::Address &addr) const override;
	bool isNameUsed(const std::string &name, const ghidra::Scope *op2) const override { throw ghidra::LowlevelError("isNameUsed unimplemented"); }
	ghidra::Funcdata *resolveExternalRefFunction(ghidra::ExternRefSymbol *sym) const override;

	ghidra::SymbolEntry *findOverlap(const ghidra::Address &addr,ghidra::int4 size) const override { throw LowlevelError("findOverlap unimplemented"); }
	ghidra::SymbolEntry *findBefore(const ghidra::Address &addr) const				{ throw ghidra::LowlevelError("findBefore unimplemented"); }
	ghidra::SymbolEntry *findAfter(const ghidra::Address &addr) const				{ throw ghidra::LowlevelError("findAfter unimplemented"); }
	void findByName(const std::string &name,std::vector<ghidra::Symbol *> &res) const	override { throw ghidra::LowlevelError("findByName unimplemented"); }
	ghidra::MapIterator begin() const override								{ throw ghidra::LowlevelError("begin unimplemented"); }
	ghidra::MapIterator end() const override								{ throw ghidra::LowlevelError("end unimplemented"); }
	std::list<ghidra::SymbolEntry>::const_iterator beginDynamic() const override	{ throw ghidra::LowlevelError("beginDynamic unimplemented"); }
	std::list<ghidra::SymbolEntry>::const_iterator endDynamic() const override	{ throw ghidra::LowlevelError("endDynamic unimplemented"); }
	std::list<ghidra::SymbolEntry>::iterator beginDynamic() override				{ throw ghidra::LowlevelError("beginDynamic unimplemented"); }
	std::list<ghidra::SymbolEntry>::iterator endDynamic() override				{ throw ghidra::LowlevelError("endDynamic unimplemented"); }
	void clearCategory(ghidra::int4 cat) override							{ throw ghidra::LowlevelError("clearCategory unimplemented"); }
	void clearUnlockedCategory(ghidra::int4 cat) override					{ throw ghidra::LowlevelError("clearUnlockedCategory unimplemented"); }
	void clearUnlocked() override									{ throw ghidra::LowlevelError("clearUnlocked unimplemented"); }
	void restrictScope(ghidra::Funcdata *f) override						{ throw ghidra::LowlevelError("restrictScope unimplemented"); }
	void removeSymbolMappings(ghidra::Symbol *symbol) override				{ throw ghidra::LowlevelError("removeSymbolMappings unimplemented"); }
	void removeSymbol(ghidra::Symbol *symbol) override						{ throw ghidra::LowlevelError("removeSymbol unimplemented"); }
	void renameSymbol(ghidra::Symbol *sym,const std::string &newname) override	{ throw ghidra::LowlevelError("renameSymbol unimplemented"); }
	void retypeSymbol(ghidra::Symbol *sym,ghidra::Datatype *ct) override			{ throw ghidra::LowlevelError("retypeSymbol unimplemented"); }
	std::string makeNameUnique(const std::string &nm) const override			{ throw ghidra::LowlevelError("makeNameUnique unimplemented"); }
	void encode(ghidra::Encoder &encoder) const override { cache->encode(encoder); }
	void decode(ghidra::Decoder &decoder) override { throw ghidra::LowlevelError("not implemented"); }
	void printEntries(std::ostream &s) const override					{ throw ghidra::LowlevelError("printEntries unimplemented"); }
	ghidra::int4 getCategorySize(ghidra::int4 cat) const override					{ throw ghidra::LowlevelError("getCategorySize unimplemented"); }
	ghidra::Symbol *getCategorySymbol(ghidra::int4 cat,ghidra::int4 ind) const override		{ throw ghidra::LowlevelError("getCategorySymbol unimplemented"); }
	void setCategory(ghidra::Symbol *sym,ghidra::int4 cat,ghidra::int4 ind) override		{ throw ghidra::LowlevelError("setCategory unimplemented"); }
};

#endif //R2GHIDRA_R2SCOPE_H
