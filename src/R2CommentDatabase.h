/* r2ghidra - LGPL - Copyright 2019-2023 - thestr4ng3r, pancake */

#ifndef R2GHIDRA_R2COMMENTDATABASE_H
#define R2GHIDRA_R2COMMENTDATABASE_H

#include <comment.hh>

using namespace ghidra;

class R2Architecture;

class R2CommentDatabase : public CommentDatabase {
	R2Architecture *arch;
	mutable CommentDatabaseInternal cache;
	mutable bool cache_filled;
	void fillCache(const Address &fad) const;

public:
	R2CommentDatabase(R2Architecture *arch);

	void clear() override;
	void clearType(const Address &fad, uint4 tp) override;

	void addComment(uint4 tp, const Address &fad, const Address &ad, const string &txt) override;
	bool addCommentNoDuplicate(uint4 tp, const Address &fad, const Address &ad, const string &txt) override;

	void deleteComment(Comment *com) override {
		throw LowlevelError("deleteComment unimplemented");
	}

	CommentSet::const_iterator beginComment(const Address &fad) const override;
	CommentSet::const_iterator endComment(const Address &fad) const override;

	void encode(Encoder &encoder) const override { cache.encode(encoder); }
	void decode(Decoder &decoder) override { throw LowlevelError("CommentDatabaseGhidra::decode unimplemented"); }
};

#endif //R2GHIDRA_R2COMMENTDATABASE_H
