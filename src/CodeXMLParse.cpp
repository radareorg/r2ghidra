// SPDX-FileCopyrightText: 2019-2022 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "CodeXMLParse.h"

#ifdef LoadImage
#undef LoadImage
#endif

#include <funcdata.hh>
#include <r_util.h>
#include "r_util/r_xml.h"

#if R2_VERSION_NUMBER < 60104
#error r2ghidra requires radare2 >= 6.1.4 for the rxml API
#endif
#include <sstream>
#include <string>

using namespace ghidra;

struct ParseCodeXMLContext {
	ghidra::Funcdata *func;
	std::map<uintm, PcodeOp *> ops;
	std::map<ut64, Varnode *> varnodes;
	std::map<ut64, Symbol *> symbols;

	explicit ParseCodeXMLContext(ghidra::Funcdata *func) : func (func) {
		for (auto it=func->beginOpAll (); it != func->endOpAll (); it++) {
			ops[it->first.getTime ()] = it->second;
		}
		for (auto it = func->beginLoc (); it != func->endLoc (); it++) {
			varnodes[(*it)->getCreateIndex ()] = *it;
		}

		ScopeLocal *mapLocal = func->getScopeLocal ();
		MapIterator iter = mapLocal->begin ();
		MapIterator enditer = mapLocal->end ();
		for (; iter != enditer; iter++) {
			const SymbolEntry *entry = *iter;
			Symbol *sym = entry->getSymbol();
			symbols[sym->getId ()] = sym;
		}
	}
};

#define ANNOTATOR_PARAMS RXmlNode *node, ParseCodeXMLContext *ctx, std::vector<RCodeMetaItem> *out

void AnnotateOpref(ANNOTATOR_PARAMS) {
	const char *opref_str = rxml_dom_get_attribute(node, "opref");
	if (!opref_str) {
		return;
	}
	ut64 opref = r_num_get(NULL, opref_str);
	if (opref == UT64_MAX) {
		return;
	}
	auto opit = ctx->ops.find((uintm)opref);
	if (opit == ctx->ops.end()) {
		return;
	}
	auto op = opit->second;

	out->emplace_back();
	auto &annotation = out->back();
	annotation = {};
	annotation.type = R_CODEMETA_TYPE_OFFSET;
	annotation.offset.offset = op->getAddr().getOffset();
}

void AnnotateFunctionName(ANNOTATOR_PARAMS) {
	const char *func_name = rxml_dom_child_value(node);
	if (!func_name) {
		return;
	}
	RCodeMetaItem annotation = {};
	annotation.type = R_CODEMETA_TYPE_FUNCTION_NAME;
	const char *opref_str = rxml_dom_get_attribute(node, "opref");
	if (!opref_str) {
		if (ctx->func->getName() == func_name) {
			annotation.reference.name = strdup(ctx->func->getName().c_str());
			annotation.reference.offset = ctx->func->getAddress().getOffset();
			out->push_back(annotation);
			// Code below makes an offset annotation for the function name(for the currently decompiled function)
			RCodeMetaItem offsetAnnotation = {};
			offsetAnnotation.type = R_CODEMETA_TYPE_OFFSET;
			offsetAnnotation.offset.offset = annotation.reference.offset;
			out->push_back(offsetAnnotation);
		}
		return;
	}
	ut64 opref = r_num_get(NULL, opref_str);
	if (opref == UT64_MAX) {
		return;
	}
	auto opit = ctx->ops.find((uintm)opref);
	if (opit == ctx->ops.end()) {
		return;
	}
	PcodeOp *op = opit->second;
	FuncCallSpecs *call_func_spec = ctx->func->getCallSpecs(op);
	if (call_func_spec) {
		annotation.reference.name = strdup(call_func_spec->getName().c_str());
		annotation.reference.offset = call_func_spec->getEntryAddress().getOffset();
		out->push_back(annotation);
	}
}

void AnnotateCommentOffset(ANNOTATOR_PARAMS) {
	const char *off_str = rxml_dom_get_attribute(node, "off");
	if (!off_str) {
		return;
	}
	ut64 off = r_num_get(NULL, off_str);
	if (off == UT64_MAX) {
		return;
	}
	out->emplace_back();
	auto &annotation = out->back();
	annotation = {};
	annotation.type = R_CODEMETA_TYPE_OFFSET;
	annotation.offset.offset = off;
}

/**
 * Translate Ghidra's color annotations, which are essentially
 * loose token classes of the high level decompiled source code.
 **/
void AnnotateColor(ANNOTATOR_PARAMS) {
	int color = rxml_dom_attr_int(node, "color", -1);
	if (color < 0) {
		return;
	}
	RSyntaxHighlightType type;
	switch (color) {
	case Emit::syntax_highlight::keyword_color:
		type = R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD;
		break;
	case Emit::syntax_highlight::comment_color:
		type = R_SYNTAX_HIGHLIGHT_TYPE_COMMENT;
		break;
	case Emit::syntax_highlight::type_color:
		type = R_SYNTAX_HIGHLIGHT_TYPE_DATATYPE;
		break;
	case Emit::syntax_highlight::funcname_color:
		type = R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME;
		break;
	case Emit::syntax_highlight::var_color:
		type = R_SYNTAX_HIGHLIGHT_TYPE_LOCAL_VARIABLE;
		break;
	case Emit::syntax_highlight::const_color:
		type = R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE;
		break;
	case Emit::syntax_highlight::param_color:
		type = R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_PARAMETER;
		break;
	case Emit::syntax_highlight::global_color:
		type = R_SYNTAX_HIGHLIGHT_TYPE_GLOBAL_VARIABLE;
		break;
	case Emit::syntax_highlight::no_color:
#if 1
	case Emit::syntax_highlight::error_color:
	case Emit::syntax_highlight::special_color:
#endif
default:
		return;
	}
	RCodeMetaItem annotation = {};
	annotation.type = R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT;
	annotation.syntax_highlight.type = type;
	out->push_back (annotation);
}

void AnnotateGlobalVariable(Varnode *varnode, std::vector<RCodeMetaItem> *out) {
	RCodeMetaItem annotation = {};
	annotation.type = R_CODEMETA_TYPE_GLOBAL_VARIABLE;
	annotation.reference.offset = varnode->getOffset();
	out->push_back(annotation);
}

void AnnotateConstantVariable(Varnode *varnode, std::vector<RCodeMetaItem> *out) {
	RCodeMetaItem annotation = {};
	annotation.type = R_CODEMETA_TYPE_CONSTANT_VARIABLE;
	annotation.reference.offset = varnode->getOffset ();
	out->push_back (annotation);
}

// Annotates local variables and function parameters
void AnnotateLocalVariable(Symbol *symbol, std::vector<RCodeMetaItem> *out) {
	if (symbol == nullptr) {
		return;
	}
	RCodeMetaItem annotation = {};
	annotation.variable.name = strdup (symbol->getName().c_str ());
	annotation.type = (symbol->getCategory () == 0)
		? R_CODEMETA_TYPE_FUNCTION_PARAMETER
		: R_CODEMETA_TYPE_LOCAL_VARIABLE;
	out->push_back (annotation);
}

void AnnotateVariable(ANNOTATOR_PARAMS) {
	const char* varref_str = rxml_dom_get_attribute(node, "varref");
	if (!varref_str) {
		RXmlNode* parent = rxml_dom_parent(node);
		const char *parent_name = rxml_dom_name(parent);
		if (parent_name && !strcmp(parent_name, "vardecl")) {
			const char* symref_str = rxml_dom_get_attribute(parent, "symref");
			if (symref_str) {
				ut64 symref = r_num_get(NULL, symref_str);
				Symbol *symbol = ctx->symbols[symref];
				AnnotateLocalVariable (symbol, out);
			}
		}
		return;
	}
	ut64 varref = r_num_get(NULL, varref_str);
	if (varref == UT64_MAX) {
		return;
	}
	auto varrefnode = ctx->varnodes.find(varref);
	if (varrefnode == ctx->varnodes.end()) {
		return;
	}
	Varnode *varnode = varrefnode->second;
	HighVariable *high;
	try {
		high = varnode->getHigh();
	} catch (const LowlevelError &e) {
		return;
	}
	if (high->isPersist() && high->isAddrTied()) {
		AnnotateGlobalVariable(varnode, out);
	} else if (high->isConstant() && high->getType()->getMetatype() == TYPE_PTR) {
		AnnotateConstantVariable(varnode, out);
	} else if (!high->isPersist()) {
		AnnotateLocalVariable(high->getSymbol(), out);
	}
}

static const std::map<std::string, std::vector<void (*)(ANNOTATOR_PARAMS)>> annotators = {
	{ "statement", { AnnotateOpref } },
	{ "op", { AnnotateOpref, AnnotateColor } },
	{ "comment", { AnnotateCommentOffset, AnnotateColor } },
	{ "variable", { AnnotateVariable, AnnotateColor } },
	{ "funcname", { AnnotateFunctionName, AnnotateColor } },
	{ "type", { AnnotateColor } },
	{ "syntax", { AnnotateColor } }
};

/**
 * Ghidra returns an annotated AST of the decompiled high-level language code.
 * The AST is saved in XML format.
 *
 * This function is a DFS traversal over Ghidra's AST.
 * It parses some of the annotatations (e.g. decompilation offsets, token classes, ..)
 * and translates them into a suitable format
 * that can be natively saved in the RCodeMeta structure.
 **/
static void ParseNode(RXmlNode *node, ParseCodeXMLContext *ctx, std::ostream &stream, RCodeMeta *code) {
	if (rxml_dom_is_text(node)) {
		char* cleaned = strdup(node->text ? node->text : "");
		if (strlen(cleaned) > 1) {
			r_str_trim(cleaned);
		}
		stream << cleaned;
		R_FREE(cleaned);
		return;
	}

	std::vector<RCodeMetaItem> annotations;

	const char *name = rxml_dom_name(node);
	if (name && !strcmp(name, "break")) {
		stream << "\n";
		int indent = rxml_dom_attr_int(node, "indent", 0);
		stream << std::string(indent, ' ');
	} else if (name) {
		auto it = annotators.find(name);
		if (it != annotators.end()) {
			auto &callbacks = it->second;
			for (auto &callback : callbacks) {
				callback(node, ctx, &annotations);
			}
			for (auto &annotation : annotations) {
				annotation.start = stream.tellp();
			}
		}
	}

	for (RXmlNode *child = rxml_dom_first_child(node); child; child = rxml_dom_next_sibling(child)) {
		ParseNode(child, ctx, stream, code);
	}

	// an annotation applies for a node an all its children
	for (auto &annotation : annotations) {
		annotation.end = stream.tellp();
		RCodeMetaItem *item = r_codemeta_item_clone(&annotation);
		r_codemeta_add_item(code, item);
	}
}

R_API RCodeMeta *ParseCodeXML(ghidra::Funcdata *func, const char *xml) {
	RXmlNode *doc = rxml_dom_parse(xml);
	if (!doc) {
		return nullptr;
	}
	std::stringstream ss;
	RCodeMeta *code = r_codemeta_new("");
	if (!code) {
		rxml_dom_free(doc);
		return nullptr;
	}
	ParseCodeXMLContext ctx (func);
	ParseNode (rxml_dom_first_child(doc), &ctx, ss, code);
	rxml_dom_free(doc);
	std::string str = ss.str ();
	code->code = strdup (str.c_str ());
	return code;
}
