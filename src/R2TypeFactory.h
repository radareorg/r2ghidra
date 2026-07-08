// SPDX-FileCopyrightText: 2019-2021 thestr4ng3r, pancake
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R2GHIDRA_R2TYPEFACTORY_H
#define R2GHIDRA_R2TYPEFACTORY_H

#include <type.hh>

#include <map>

using namespace ghidra;
class R2Architecture;

class R2TypeFactory : public TypeFactory {
private:
	R2Architecture *arch;
	// RParseCType *ctype;

	struct CStringCacheEntry {
		Datatype *type; // nullptr = cached resolution failure
		std::string error;
	};
	// both caches live for the factory's lifetime (one decompile); Datatypes are owned by the factory
	std::map<std::string, CStringCacheEntry> cstringCache;
	std::map<std::string, Datatype *> lookupCache;

	Datatype *fromCStringInternal(const string &str, string *error, std::set<std::string> *stackTypes);

	Datatype *queryR2Struct(const string &n, std::set<std::string> &stackTypes);
	Datatype *queryR2Union(const string &n, std::set<std::string> &stackTypes);
	Datatype *queryR2Base(const string &n);
	Datatype *queryR2Enum(const string &n, std::set<std::string> &stackTypes);
	Datatype *queryR2Typedef(const string &n, std::set<std::string> &stackTypes);
	Datatype *queryR2Function(const string &n, std::set<std::string> &stackTypes);
	Datatype *queryR2(const string &n, std::set<std::string> &stackTypes);

protected:
	Datatype *findById(const string &n, uint8 id, int4 sz, std::set<std::string> &stackTypes);
	Datatype *findById(const string &n, uint8 id, int4 sz) override;
	using TypeFactory::findByName;
	Datatype *findByName(const string &n, std::set<std::string> &stackTypes) { return findById(n, 0, 0, stackTypes); }

public:
	using StackTypes = std::set<std::string>;
	R2TypeFactory(R2Architecture *arch);
	~R2TypeFactory() override;

	Datatype *fromCString(const string &str, string *error = nullptr, std::set<std::string> *stackTypes = nullptr);
};

#endif //R2GHIDRA_R2TYPEFACTORY_H
