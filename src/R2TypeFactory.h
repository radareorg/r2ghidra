/* r2ghidra - LGPL - Copyright 2019-2021 - thestr4ng3r, pancake */

#ifndef R2GHIDRA_R2TYPEFACTORY_H
#define R2GHIDRA_R2TYPEFACTORY_H

#include <type.hh>

/*
typedef struct r_parse_ctype_t RParseCType;
typedef struct r_parse_ctype_type_t RParseCTypeType;
*/

// using namespace ghidra;
class R2Architecture;

class R2TypeFactory : public ghidra::TypeFactory {
private:
	R2Architecture *arch;
	// RParseCType *ctype;

	ghidra::Datatype *queryR2Struct(const std::string &n, std::set<std::string> &stackTypes);
	ghidra::Datatype *queryR2Enum(const std::string &n);
	ghidra::Datatype *queryR2Typedef(const std::string &n, std::set<std::string> &stackTypes);
	ghidra::Datatype *queryR2(const std::string &n, std::set<std::string> &stackTypes);

protected:
	ghidra::Datatype *findById(const std::string &n, ghidra::uint8 id, ghidra::int4 sz, std::set<std::string> &stackTypes);
	ghidra::Datatype *findById(const std::string &n, ghidra::uint8 id, ghidra::int4 sz) override;
	using TypeFactory::findByName;
	ghidra::Datatype *findByName(const std::string &n, std::set<std::string> &stackTypes) { return findById(n, 0, 0, stackTypes); }

public:
	using StackTypes = std::set<std::string>;
	R2TypeFactory(R2Architecture *arch);
	~R2TypeFactory() override;

	ghidra::Datatype *fromCString(const std::string &str, std::string *error = nullptr, std::set<std::string> *stackTypes = nullptr);
//	ghidra::Datatype *fromCType(const RParseCTypeType *ctype, string *error = nullptr, std::set<std::string> *stackTypes = nullptr);
};

#endif //R2GHIDRA_R2TYPEFACTORY_H
