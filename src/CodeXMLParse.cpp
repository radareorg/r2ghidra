/* r2ghidra - LGPL - Copyright 2019-2022 - pancake */

#include "CodeXMLParse.h"

#ifdef LoadImage
#undef LoadImage
#endif

#define TEST_UNKNOWN_NODES 0
#define USE_RXML 0 /* only for r2-5.8 */

#include <funcdata.hh>
#include <r_util.h>
#if USE_RXML
#include <r_util/r_xml.h>
#else
#include <pugixml.hpp>
#endif
#include <sstream>
#include <string>

struct ParseCodeXMLContext {
	Funcdata *func;
	std::map<uintm, PcodeOp *> ops;
	std::map<ut64, Varnode *> varnodes;
	std::map<ut64, Symbol *> symbols;
	
	explicit ParseCodeXMLContext(Funcdata *func) : func (func) {
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

#define ANNOTATOR_PARAMS pugi::xml_node node, ParseCodeXMLContext *ctx, std::vector<RCodeMetaItem> *out
#define ANNOTATOR [](ANNOTATOR_PARAMS) -> void

void AnnotateOpref(ANNOTATOR_PARAMS) {
	pugi::xml_attribute attr = node.attribute ("opref");
	if (attr.empty ()) {
		return;
	}
	ut64 opref = attr.as_ullong (UT64_MAX);
	if (opref == UT64_MAX) {
		return;
	}
	auto opit = ctx->ops.find ((uintm)opref);
	if (opit == ctx->ops.end ()) {
		return;
	}
	auto op = opit->second;

	out->emplace_back ();
	auto &annotation = out->back ();
	annotation = {};
	annotation.type = R_CODEMETA_TYPE_OFFSET;
	annotation.offset.offset = op->getAddr ().getOffset ();
}

void AnnotateFunctionName(ANNOTATOR_PARAMS) {
	const char *func_name = node.child_value ();
	if (!func_name) {
		return;
	}
	RCodeMetaItem annotation = {};
	annotation.type = R_CODEMETA_TYPE_FUNCTION_NAME;
	pugi::xml_attribute attr = node.attribute ("opref");
	if (attr.empty ()) {
		if (ctx->func->getName() == func_name) {
			annotation.reference.name = strdup(ctx->func->getName().c_str());
			annotation.reference.offset = ctx->func->getAddress().getOffset();
			out->push_back(annotation);
			// Code below makes an offset annotation for the function name(for the currently decompiled function)
			RCodeMetaItem offsetAnnotation = {};
			offsetAnnotation.type = R_CODEMETA_TYPE_OFFSET;
			offsetAnnotation.offset.offset = annotation.reference.offset;
			out->push_back (offsetAnnotation);
		}
		return;
	}
	ut64 opref = attr.as_ullong (UT64_MAX);
	if (opref == UT64_MAX) {
		return;
	}
	auto opit = ctx->ops.find ((uintm)opref);
	if (opit == ctx->ops.end ()) {
		return;	
	}
	PcodeOp *op = opit->second;
	FuncCallSpecs *call_func_spec = ctx->func->getCallSpecs (op);
	if (call_func_spec) {
		annotation.reference.name = strdup (call_func_spec->getName ().c_str ());
		annotation.reference.offset = call_func_spec->getEntryAddress ().getOffset ();
		out->push_back (annotation);
	}
}

void AnnotateCommentOffset(ANNOTATOR_PARAMS) {
	pugi::xml_attribute attr = node.attribute("off");
	if (attr.empty()) {
		return;
	}
	ut64 off = attr.as_ullong(UT64_MAX);
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
	pugi::xml_attribute attr = node.attribute("color");
	if (attr.empty ()) {
		return;
	}
	std::string color = attr.as_string();
	RSyntaxHighlightType type;
	if (color == "keyword") {
		type = R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD;
	} else if (color == "comment") {
		type = R_SYNTAX_HIGHLIGHT_TYPE_COMMENT;
	} else if (color == "type") {
		type = R_SYNTAX_HIGHLIGHT_TYPE_DATATYPE;
	} else if (color == "funcname") {
		type = R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME;
	} else if (color == "param") {
		type = R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_PARAMETER;
	} else if (color == "var") {
		type = R_SYNTAX_HIGHLIGHT_TYPE_LOCAL_VARIABLE;
	} else if (color == "const") {
		type = R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE;
	} else if (color == "global") {
		type = R_SYNTAX_HIGHLIGHT_TYPE_GLOBAL_VARIABLE;
	} else {
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
	pugi::xml_attribute attr = node.attribute ("varref");
	if (attr.empty ()) {
		auto node_parent = node.parent ();
		if (std::string("vardecl") == node_parent.name ()) {
			pugi::xml_attribute attributeSymbolId = node_parent.attribute ("symref");
			ut64 symref = attributeSymbolId.as_ullong(UT64_MAX);
			Symbol *symbol = ctx->symbols[symref];
			AnnotateLocalVariable (symbol, out);
		}
		return;
	}
	ut64 varref = attr.as_ullong(UT64_MAX);
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

static const std::map<std::string, std::vector <void (*)(ANNOTATOR_PARAMS)> > annotators = {
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
static void ParseNode(pugi::xml_node node, ParseCodeXMLContext *ctx, std::ostream &stream, RCodeMeta *code) {
	// A leaf is an XML node which contains parts of the high level decompilation language
	if (node.type() == pugi::xml_node_type::node_pcdata) {
		stream << node.value();
		return;
	}

	std::vector<RCodeMetaItem> annotations;
#if TEST_UNKNOWN_NODES
	bool close_test = false;
	static const std::set<std::string> boring_tags = { "syntax" };
#endif

	if (std::string("break") == node.name()) {
		stream << "\n";
		stream << std::string(node.attribute("indent").as_uint(0), ' ');
	} else {
		auto it = annotators.find(node.name());
		if (it != annotators.end()) {
			auto &callbacks = it->second;
			for (auto &callback : callbacks) {
				callback(node, ctx, &annotations);
			}
			for (auto &annotation : annotations) {
				annotation.start = stream.tellp();
			}
		}
#if TEST_UNKNOWN_NODES
		else if (boring_tags.find(node.name()) == boring_tags.end()) {
			close_test = true;
			stream << "<" << node.name();
			for (pugi::xml_attribute attr : node.attributes()) {
				stream << " " << attr.name() << "=\"" << attr.value() << "\""; // unescaped, but who cares
			}
			stream << ">";
		}
#endif
	}

	for (pugi::xml_node child : node) {
		ParseNode(child, ctx, stream, code);
	}

	// an annotation applies for a node an all its children
	for (auto &annotation : annotations) {
		annotation.end = stream.tellp();
		RCodeMetaItem *item = r_codemeta_item_clone (&annotation);
		r_codemeta_add_item (code, item);
	}
#if TEST_UNKNOWN_NODES
	if (close_test) {
		stream << "</" << node.name() << ">";
	}
#endif
}

R_API RCodeMeta *ParseCodeXML(Funcdata *func, const char *xml) {
	pugi::xml_document doc;
	if(!doc.load_string (xml, pugi::parse_default | pugi::parse_ws_pcdata)) {
		return nullptr;
	}
	std::stringstream ss;
	RCodeMeta *code = r_codemeta_new(nullptr);
	if (!code) {
		return nullptr;
	}
	ParseCodeXMLContext ctx (func);
	ParseNode (doc.child ("function"), &ctx, ss, code);
	std::string str = ss.str ();
	code->code = strdup (str.c_str ());
	return code;
}
