/* r2ghidra - LGPL - Copyright 2019-2023 - thestr4ng3r, pancake */

#ifndef R2GHIDRA_R2COMMENTDATABASE_H
#define R2GHIDRA_R2COMMENTDATABASE_H

#include <comment.hh>

// using namespace ghidra;

class R2Architecture;

class R2CommentDatabase : public ghidra::CommentDatabase {
	R2Architecture *arch;
	mutable ghidra::CommentDatabaseInternal cache;
	mutable bool cache_filled;
	void fillCache(const ghidra::Address &fad) const;

public:
	R2CommentDatabase(R2Architecture *arch);

	void clear() override;
	void clearType(const ghidra::Address &fad, ghidra::uint4 tp) override;

	void addComment(ghidra::uint4 tp, const ghidra::Address &fad, const ghidra::Address &ad, const std::string &txt) override;
	bool addCommentNoDuplicate(ghidra::uint4 tp, const ghidra::Address &fad, const ghidra::Address &ad, const std::string &txt) override;

	void deleteComment(ghidra::Comment *com) override {
		throw ghidra::LowlevelError("deleteComment unimplemented");
	}

	ghidra::CommentSet::const_iterator beginComment(const ghidra::Address &fad) const override;
	ghidra::CommentSet::const_iterator endComment(const ghidra::Address &fad) const override;

	void encode(ghidra::Encoder &encoder) const override { cache.encode(encoder); }
	void decode(ghidra::Decoder &decoder) override { throw ghidra::LowlevelError("CommentDatabaseGhidra::decode unimplemented"); }
};

#endif //R2GHIDRA_R2COMMENTDATABASE_H
