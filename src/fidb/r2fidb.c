#include <r_bin.h>
#include <r_util.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GHIDRA_GBF_MAGIC 0x2f30312c34292c2aULL

#define NODE_LONGKEY_INTERIOR 0
#define NODE_LONGKEY_VAR_REC 1
#define NODE_LONGKEY_FIXED_REC 2
#define NODE_CHAINED_INDEX 8
#define NODE_CHAINED_DATA 9

#define FIELD_BYTE 0
#define FIELD_SHORT 1
#define FIELD_INT 2
#define FIELD_LONG 3
#define FIELD_STRING 4
#define FIELD_BINARY 5
#define FIELD_BOOL 6
#define FIELD_FIXED10 7
#define FIELD_EXTENSION 0xff

typedef struct {
	ut8 *buf;
	size_t size;
	int block_size;
	int buffer_size;
	int root_id;
} FidFile;

typedef struct {
	ut64 key;
	char *name;
	int version;
	int root_id;
	ut8 key_type;
	ut8 *field_types;
	int field_type_count;
	char *field_names;
	int index_col;
	st64 max_key;
	int record_count;
} TableInfo;

typedef struct {
	TableInfo *v;
	int n;
	int cap;
} TableVec;

typedef struct {
	ut64 key;
	char *family;
	char *version;
	char *variant;
	char *ghidra_version;
	char *language_id;
	int language_version;
	int language_minor_version;
	char *compiler_spec_id;
} LibraryRec;

typedef struct {
	LibraryRec *v;
	int n;
	int cap;
} LibraryVec;

typedef struct {
	ut64 key;
	char *value;
} StringRec;

typedef struct {
	StringRec *v;
	int n;
	int cap;
} StringVec;

typedef struct {
	ut64 key;
	ut16 code_unit_size;
	ut64 full_hash;
	ut8 specific_hash_additional_size;
	ut64 specific_hash;
	ut64 library_id;
	ut64 name_id;
	ut64 entry_point;
	ut64 domain_path_id;
	ut8 flags;
} FunctionRec;

typedef struct {
	FunctionRec *v;
	int n;
	int cap;
} FunctionVec;

typedef struct {
	TableVec tables;
	LibraryVec libraries;
	StringVec strings;
	FunctionVec functions;
	int inferior_relations;
	int superior_relations;
} FidDb;

typedef bool (*RecordCb)(FidFile *ff, ut64 key, const ut8 *record, int record_len, void *user);

static st32 read_be32s (const ut8 *p) {
	return (st32)r_read_be32 (p);
}

static char *dup_range0 (const ut8 *p, int len) {
	if (len < 0) {
		return NULL;
	}
	char *s = R_NEWS (char, len + 1);
	if (!s) {
		return NULL;
	}
	memcpy (s, p, (size_t)len);
	s[len] = 0;
	return s;
}

static bool fits_records (int base, int count, int size, int limit) {
	return count >= 0 && size > 0 &&
		(!count || (base <= limit && count <= (limit - base) / size));
}

static const ut8 *get_buffer(FidFile *ff, int id) {
	if (id < 0 || ff->block_size <= 5) {
		return NULL;
	}
	ut64 off = ((ut64)id + 1) * (ut64)ff->block_size;
	if (off + (ut64)ff->block_size > ff->size) {
		return NULL;
	}
	const ut8 *block = ff->buf + off;
	if ((block[0] & 1) || read_be32s (block + 1) != id) {
		return NULL;
	}
	return block + 5;
}

static int fixed_len_for_schema(const ut8 *types, int n) {
	int len = 0;
	for (int i = 0; i < n; i++) {
		switch (types[i]) {
		case FIELD_BYTE:
		case FIELD_BOOL:
			len += 1;
			break;
		case FIELD_SHORT:
			len += 2;
			break;
		case FIELD_INT:
			len += 4;
			break;
		case FIELD_LONG:
			len += 8;
			break;
		case FIELD_FIXED10:
			len += 10;
			break;
		default:
			return 0;
		}
	}
	return len;
}

static bool schema_is_variable(const ut8 *types, int n) {
	for (int i = 0; i < n; i++) {
		if (types[i] == FIELD_STRING || types[i] == FIELD_BINARY) {
			return true;
		}
	}
	return false;
}

static void table_vec_fini(TableVec *vec) {
	for (int i = 0; i < vec->n; i++) {
		free (vec->v[i].name);
		free (vec->v[i].field_types);
		free (vec->v[i].field_names);
	}
	free (vec->v);
}

static void library_vec_fini(LibraryVec *vec) {
	for (int i = 0; i < vec->n; i++) {
		free (vec->v[i].family);
		free (vec->v[i].version);
		free (vec->v[i].variant);
		free (vec->v[i].ghidra_version);
		free (vec->v[i].language_id);
		free (vec->v[i].compiler_spec_id);
	}
	free (vec->v);
}

static void string_vec_fini(StringVec *vec) {
	for (int i = 0; i < vec->n; i++) {
		free (vec->v[i].value);
	}
	free (vec->v);
}

static void function_vec_fini(FunctionVec *vec) {
	free (vec->v);
}

static void fid_db_fini(FidDb *db) {
	table_vec_fini (&db->tables);
	library_vec_fini (&db->libraries);
	string_vec_fini (&db->strings);
	function_vec_fini (&db->functions);
}

static bool table_vec_push(TableVec *vec, TableInfo *it) {
	if (vec->n == vec->cap) {
		int ncap = vec->cap? vec->cap * 2: 16;
		TableInfo *nv = realloc (vec->v, (size_t)ncap * sizeof (*nv));
		if (!nv) {
			return false;
		}
		vec->v = nv;
		vec->cap = ncap;
	}
	vec->v[vec->n++] = *it;
	return true;
}

static bool library_vec_push(LibraryVec *vec, LibraryRec *it) {
	if (vec->n == vec->cap) {
		int ncap = vec->cap? vec->cap * 2: 8;
		LibraryRec *nv = realloc (vec->v, (size_t)ncap * sizeof (*nv));
		if (!nv) {
			return false;
		}
		vec->v = nv;
		vec->cap = ncap;
	}
	vec->v[vec->n++] = *it;
	return true;
}

static bool string_vec_push(StringVec *vec, StringRec *it) {
	if (vec->n == vec->cap) {
		int ncap = vec->cap? vec->cap * 2: 1024;
		StringRec *nv = realloc (vec->v, (size_t)ncap * sizeof (*nv));
		if (!nv) {
			return false;
		}
		vec->v = nv;
		vec->cap = ncap;
	}
	vec->v[vec->n++] = *it;
	return true;
}

static bool function_vec_push(FunctionVec *vec, FunctionRec *it) {
	if (vec->n == vec->cap) {
		int ncap = vec->cap? vec->cap * 2: 4096;
		FunctionRec *nv = realloc (vec->v, (size_t)ncap * sizeof (*nv));
		if (!nv) {
			return false;
		}
		vec->v = nv;
		vec->cap = ncap;
	}
	vec->v[vec->n++] = *it;
	return true;
}

static bool read_field_string(const ut8 *record, int record_len, int *off, char **out) {
	if (*off + 4 > record_len) {
		return false;
	}
	int len = read_be32s (record + *off);
	*off += 4;
	if (len < 0) {
		*out = NULL;
		return true;
	}
	if (len > record_len - *off) {
		return false;
	}
	*out = dup_range0 (record + *off, len);
	*off += len;
	return *out != NULL;
}

static bool read_field_binary(const ut8 *record, int record_len, int *off, ut8 **out, int *out_len) {
	if (*off + 4 > record_len) {
		return false;
	}
	int len = read_be32s (record + *off);
	*off += 4;
	if (len < 0) {
		*out = NULL;
		*out_len = 0;
		return true;
	}
	if (len > record_len - *off) {
		return false;
	}
	ut8 *b = len? r_mem_dup (record + *off, len): NULL;
	if (len && !b) {
		return false;
	}
	*out = b;
	*out_len = len;
	*off += len;
	return true;
}

static ut8 *read_chained(FidFile *ff, int id, int *out_len) {
	const ut8 *first = get_buffer (ff, id);
	if (!first || ff->buffer_size < 5) {
		return NULL;
	}
	int size = read_be32s (first + 1);
	bool xored = false;
	if (size < 0) {
		xored = true;
		size &= 0x7fffffff;
	}
	if (size <= 0) {
		return NULL;
	}
	ut8 *out = R_NEWS0 (ut8, size);
	if (!out) {
		return NULL;
	}
	if (first[0] == NODE_CHAINED_DATA) {
		int n = R_MIN (size, ff->buffer_size - 5);
		if (n > 0) {
			memcpy (out, first + 5, (size_t)n);
		}
	} else if (first[0] == NODE_CHAINED_INDEX) {
		int data_space = ff->buffer_size - 1;
		int indexes_per_buffer = (ff->buffer_size - 9) / 4;
		if (indexes_per_buffer <= 0) {
			free (out);
			return NULL;
		}
		int index_count = ((size - 1) / data_space) + 1;
		int out_off = 0;
		const ut8 *ib = first;
		int ix = 0;
		for (int i = 0; i < index_count; i++) {
			if (ix == indexes_per_buffer) {
				int next_id = read_be32s (ib + 5);
				ib = get_buffer (ff, next_id);
				if (!ib) {
					free (out);
					return NULL;
				}
				ix = 0;
			}
			int data_id = read_be32s (ib + 9 + (ix * 4));
			int n = R_MIN (data_space, size - out_off);
			if (data_id >= 0) {
				const ut8 *db = get_buffer (ff, data_id);
				if (!db) {
					free (out);
					return NULL;
				}
				memcpy (out + out_off, db + 1, (size_t)n);
			}
			out_off += n;
			ix++;
		}
	} else {
		free (out);
		return NULL;
	}
	if (xored) {
		eprintf ("warning: obfuscated chained buffers are not supported\n");
	}
	*out_len = size;
	return out;
}

static bool walk_long_table(FidFile *ff, int root_id, const ut8 *types, int type_count, RecordCb cb, void *user);

static bool walk_long_node(FidFile *ff, int node_id, const ut8 *types, int type_count, int fixed_len, RecordCb cb, void *user) {
	const ut8 *node = get_buffer (ff, node_id);
	if (!node) {
		return false;
	}
	int key_count = read_be32s (node + 1);
	if (key_count < 0) {
		return false;
	}
	int buffer_size = ff->buffer_size;
	switch (node[0]) {
	case NODE_LONGKEY_INTERIOR:
		if (!fits_records (5, key_count, 12, buffer_size)) {
			return false;
		}
		for (int i = 0; i < key_count; i++) {
			int child = read_be32s (node + 5 + (i * 12) + 8);
			if (!walk_long_node (ff, child, types, type_count, fixed_len, cb, user)) {
				return false;
			}
		}
		return true;
	case NODE_LONGKEY_VAR_REC:
		if (!fits_records (13, key_count, 13, buffer_size)) {
			return false;
		}
		for (int i = 0; i < key_count; i++) {
			int ent = 13 + (i * 13);
			ut64 key = r_read_be64 (node + ent);
			int off = read_be32s (node + ent + 8);
			bool indirect = node[ent + 12] != 0;
			if (indirect) {
				if (off < 0 || off + 4 > ff->buffer_size) {
					return false;
				}
				int chained_id = read_be32s (node + off);
				int chained_len = 0;
				ut8 *chained = read_chained (ff, chained_id, &chained_len);
				if (!chained) {
					return false;
				}
				bool ok = cb (ff, key, chained, chained_len, user);
				free (chained);
				if (!ok) {
					return false;
				}
			} else {
				int next = (i == 0)? ff->buffer_size: read_be32s (node + ent - 5);
				int len = next - off;
				if (off < 0 || len < 0 || off + len > ff->buffer_size) {
					return false;
				}
				if (!cb (ff, key, node + off, len, user)) {
					return false;
				}
			}
		}
		return true;
	case NODE_LONGKEY_FIXED_REC:
		if (!fits_records (13, key_count, 8 + fixed_len, buffer_size)) {
			return false;
		}
		for (int i = 0; i < key_count; i++) {
			int off = 13 + (i * (8 + fixed_len));
			ut64 key = r_read_be64 (node + off);
			if (!cb (ff, key, node + off + 8, fixed_len, user)) {
				return false;
			}
		}
		return true;
	default:
		return false;
	}
}

static bool walk_long_table(FidFile *ff, int root_id, const ut8 *types, int type_count, RecordCb cb, void *user) {
	if (root_id < 0) {
		return true;
	}
	int fixed_len = schema_is_variable (types, type_count)? 0: fixed_len_for_schema (types, type_count);
	return walk_long_node (ff, root_id, types, type_count, fixed_len, cb, user);
}

static bool parse_master_record(FidFile *ff, ut64 key, const ut8 *record, int record_len, void *user) {
	/* unused: ff */ (void)ff;
	TableVec *tables = (TableVec *)user;
	int off = 0;
	TableInfo t = {0};
	t.key = key;
	if (!read_field_string (record, record_len, &off, &t.name)) {
		goto beach;
	}
	if (off + 4 + 4 + 1 > record_len) {
		goto beach;
	}
	t.version = read_be32s (record + off);
	off += 4;
	t.root_id = read_be32s (record + off);
	off += 4;
	t.key_type = record[off++];
	if (!read_field_binary (record, record_len, &off, &t.field_types, &t.field_type_count)) {
		goto beach;
	}
	if (!read_field_string (record, record_len, &off, &t.field_names)) {
		goto beach;
	}
	if (off + 4 + 8 + 4 > record_len) {
		goto beach;
	}
	t.index_col = read_be32s (record + off);
	off += 4;
	t.max_key = (st64)r_read_be64 (record + off);
	off += 8;
	t.record_count = read_be32s (record + off);
	return table_vec_push (tables, &t);
beach:
	free (t.name);
	free (t.field_types);
	free (t.field_names);
	return false;
}

static bool parse_library_record(FidFile *ff, ut64 key, const ut8 *record, int record_len, void *user) {
	/* unused: ff */ (void)ff;
	LibraryVec *libs = (LibraryVec *)user;
	LibraryRec l = {0};
	int off = 0;
	l.key = key;
	if (!read_field_string (record, record_len, &off, &l.family) ||
		!read_field_string (record, record_len, &off, &l.version) ||
		!read_field_string (record, record_len, &off, &l.variant) ||
		!read_field_string (record, record_len, &off, &l.ghidra_version) ||
		!read_field_string (record, record_len, &off, &l.language_id)) {
		goto beach;
	}
	if (off + 8 > record_len) {
		goto beach;
	}
	l.language_version = read_be32s (record + off);
	off += 4;
	l.language_minor_version = read_be32s (record + off);
	off += 4;
	if (!read_field_string (record, record_len, &off, &l.compiler_spec_id)) {
		goto beach;
	}
	return library_vec_push (libs, &l);
beach:
	free (l.family);
	free (l.version);
	free (l.variant);
	free (l.ghidra_version);
	free (l.language_id);
	free (l.compiler_spec_id);
	return false;
}

static bool parse_string_record(FidFile *ff, ut64 key, const ut8 *record, int record_len, void *user) {
	/* unused: ff */ (void)ff;
	StringVec *strings = (StringVec *)user;
	StringRec s = {0};
	int off = 0;
	s.key = key;
	if (!read_field_string (record, record_len, &off, &s.value)) {
		return false;
	}
	return string_vec_push (strings, &s);
}

static bool parse_function_record(FidFile *ff, ut64 key, const ut8 *record, int record_len, void *user) {
	/* unused: ff */ (void)ff;
	if (record_len < 52) {
		return false;
	}
	FunctionVec *funcs = (FunctionVec *)user;
	FunctionRec f = {0};
	int off = 0;
	f.key = key;
	f.code_unit_size = r_read_be16 (record + off);
	off += 2;
	f.full_hash = r_read_be64 (record + off);
	off += 8;
	f.specific_hash_additional_size = record[off++];
	f.specific_hash = r_read_be64 (record + off);
	off += 8;
	f.library_id = r_read_be64 (record + off);
	off += 8;
	f.name_id = r_read_be64 (record + off);
	off += 8;
	f.entry_point = r_read_be64 (record + off);
	off += 8;
	f.domain_path_id = r_read_be64 (record + off);
	off += 8;
	f.flags = record[off];
	return function_vec_push (funcs, &f);
}

static bool count_record(FidFile *ff, ut64 key, const ut8 *record, int record_len, void *user) {
	(void)ff;
	(void)key;
	(void)record;
	(void)record_len;
	int *count = (int *)user;
	(*count)++;
	return true;
}

static TableInfo *find_primary_table(TableVec *tables, const char *name) {
	for (int i = 0; i < tables->n; i++) {
		TableInfo *t = &tables->v[i];
		if (t->index_col == -1 && t->name && !strcmp (t->name, name)) {
			return t;
		}
	}
	return NULL;
}

static const char *string_lookup(StringVec *strings, ut64 key) {
	int lo = 0;
	int hi = strings->n - 1;
	while (lo <= hi) {
		int mid = lo + ((hi - lo) / 2);
		if (strings->v[mid].key == key) {
			return strings->v[mid].value? strings->v[mid].value: "";
		}
		if (strings->v[mid].key < key) {
			lo = mid + 1;
		} else {
			hi = mid - 1;
		}
	}
	return "";
}

static LibraryRec *library_lookup(LibraryVec *libs, ut64 key) {
	for (int i = 0; i < libs->n; i++) {
		if (libs->v[i].key == key) {
			return &libs->v[i];
		}
	}
	return NULL;
}

static int function_limit(FidDb *db, int limit) {
	return (limit > 0 && limit < db->functions.n)? limit: db->functions.n;
}

static bool fid_load_file(const char *path, FidFile *ff) {
	size_t sz = 0;
	ut8 *buf = (ut8 *)r_file_slurp (path, &sz);
	if (!buf || sz < 0x40) {
		free (buf);
		return false;
	}
	ut64 magic = r_read_be64 (buf);
	int header_version = read_be32s (buf + 16);
	int block_size = read_be32s (buf + 20);
	if (magic != GHIDRA_GBF_MAGIC || header_version != 1 || block_size < 15 || (sz % (size_t)block_size)) {
		free (buf);
		return false;
	}
	ff->buf = buf;
	ff->size = sz;
	ff->block_size = block_size;
	ff->buffer_size = block_size - 5;
	const ut8 *parms = get_buffer (ff, 0);
	if (!parms || parms[0] != NODE_CHAINED_DATA || read_be32s (parms + 1) < 10 || parms[5] != 1) {
		free (buf);
		memset (ff, 0, sizeof (*ff));
		return false;
	}
	ff->root_id = read_be32s (parms + 6);
	return true;
}

static bool fid_parse(FidFile *ff, FidDb *db) {
	static const ut8 master_schema[] = {
		FIELD_STRING, FIELD_INT, FIELD_INT, FIELD_BYTE, FIELD_BINARY, FIELD_STRING, FIELD_INT, FIELD_LONG, FIELD_INT
	};
	if (!walk_long_table (ff, ff->root_id, master_schema, R_ARRAY_SIZE (master_schema), parse_master_record, &db->tables)) {
		return false;
	}
	TableInfo *libs = find_primary_table (&db->tables, "Libraries Table");
	TableInfo *strings = find_primary_table (&db->tables, "Strings Table");
	TableInfo *functions = find_primary_table (&db->tables, "Functions Table");
	TableInfo *inferior = find_primary_table (&db->tables, "Inferior Table");
	TableInfo *superior = find_primary_table (&db->tables, "Superior Table");
	if (!libs || !strings || !functions) {
		return false;
	}
	if (!walk_long_table (ff, libs->root_id, libs->field_types, libs->field_type_count, parse_library_record, &db->libraries)) {
		return false;
	}
	if (!walk_long_table (ff, strings->root_id, strings->field_types, strings->field_type_count, parse_string_record, &db->strings)) {
		return false;
	}
	if (!walk_long_table (ff, functions->root_id, functions->field_types, functions->field_type_count, parse_function_record, &db->functions)) {
		return false;
	}
	if (inferior) {
		(void)walk_long_table (ff, inferior->root_id, inferior->field_types, inferior->field_type_count, count_record, &db->inferior_relations);
	}
	if (superior) {
		(void)walk_long_table (ff, superior->root_id, superior->field_types, superior->field_type_count, count_record, &db->superior_relations);
	}
	return true;
}

static char *clean_line(const char *s) {
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return strdup ("");
	}
	for (const ut8 *p = (const ut8 *)(s? s: ""); *p; p++) {
		if (*p == '\n' || *p == '\r' || *p == '\t') {
			r_strbuf_append (sb, " ");
		} else if (*p >= 0x20) {
			r_strbuf_append_n (sb, (const char *)p, 1);
		}
	}
	return r_strbuf_drain (sb);
}

static char *zigname_for(const char *name, ut64 key) {
	RStrBuf *sb = r_strbuf_new ("fid.");
	if (!sb) {
		return NULL;
	}
	int used = 0;
	for (const ut8 *p = (const ut8 *)(name? name: "sub"); *p && used < 96; p++) {
		char ch = (char)*p;
		if (IS_DIGIT (ch) || IS_UPPER (ch) || IS_LOWER (ch) || ch == '_' || ch == '.') {
			r_strbuf_append_n (sb, &ch, 1);
		} else {
			r_strbuf_append (sb, "_");
		}
		used++;
	}
	r_strbuf_appendf (sb, ".%08x", (ut32)key);
	return r_strbuf_drain (sb);
}

static void print_tables(FidDb *db) {
	printf ("Tables:\n");
	for (int i = 0; i < db->tables.n; i++) {
		TableInfo *t = &db->tables.v[i];
		printf ("  %-18s version=%d root=%d index_col=%d records=%d\n",
			t->name? t->name: "", t->version, t->root_id, t->index_col, t->record_count);
	}
}

static void print_libraries(FidDb *db) {
	printf ("Libraries:\n");
	for (int i = 0; i < db->libraries.n; i++) {
		LibraryRec *l = &db->libraries.v[i];
		printf ("  0x%016"PFMT64x" %s %s %s ghidra=%s lang=%s.%d.%d compiler=%s\n",
			l->key, l->family? l->family: "", l->version? l->version: "",
			l->variant? l->variant: "", l->ghidra_version? l->ghidra_version: "",
			l->language_id? l->language_id: "", l->language_version,
			l->language_minor_version, l->compiler_spec_id? l->compiler_spec_id: "");
	}
}

static void print_functions(FidDb *db, int limit) {
	int n = function_limit (db, limit);
	printf ("Functions%s:\n", n == db->functions.n? "": " (limited)");
	for (int i = 0; i < n; i++) {
		FunctionRec *f = &db->functions.v[i];
		LibraryRec *l = library_lookup (&db->libraries, f->library_id);
		const char *name = string_lookup (&db->strings, f->name_id);
		const char *path = string_lookup (&db->strings, f->domain_path_id);
		printf ("  0x%016"PFMT64x" full=0x%016"PFMT64x" specific=0x%016"PFMT64x" size=%u entry=0x%016"PFMT64x" flags=0x%02x lib=\"%s %s %s\" name=\"%s\" path=\"%s\"\n",
			f->key, f->full_hash, f->specific_hash, f->code_unit_size, f->entry_point, f->flags,
			l && l->family? l->family: "", l && l->version? l->version: "",
			l && l->variant? l->variant: "", name, path);
	}
}

static void print_tsv(FidDb *db, int limit) {
	int n = function_limit (db, limit);
	printf ("function_id\tfull_hash\tspecific_hash\tcode_unit_size\tspecific_additional_size\tentry\tflags\tlibrary\tname\tpath\n");
	for (int i = 0; i < n; i++) {
		FunctionRec *f = &db->functions.v[i];
		LibraryRec *l = library_lookup (&db->libraries, f->library_id);
		const char *name = string_lookup (&db->strings, f->name_id);
		const char *path = string_lookup (&db->strings, f->domain_path_id);
		printf ("0x%016"PFMT64x"\t0x%016"PFMT64x"\t0x%016"PFMT64x"\t%u\t%u\t0x%016"PFMT64x"\t0x%02x\t%s %s %s\t%s\t%s\n",
			f->key, f->full_hash, f->specific_hash, f->code_unit_size,
			f->specific_hash_additional_size, f->entry_point, f->flags,
			l && l->family? l->family: "", l && l->version? l->version: "",
			l && l->variant? l->variant: "", name, path);
	}
}

static bool is_c_ident(const char *s) {
	if (!s || !*s) {
		return false;
	}
	if (!(isalpha ((unsigned char)*s) || *s == '_')) {
		return false;
	}
	for (const char *p = s + 1; *p; p++) {
		if (!(isalnum ((unsigned char)*p) || *p == '_')) {
			return false;
		}
	}
	return true;
}

static char *c_comment(const char *s) {
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	for (const ut8 *p = (const ut8 *)(s? s: ""); *p; p++) {
		if (*p == '/' && p[1] == '*') {
			r_strbuf_append (sb, "/_");
			p++;
		} else if (*p == '*' && p[1] == '/') {
			r_strbuf_append (sb, "_/");
			p++;
		} else if (*p == '\n' || *p == '\r' || *p == '\t') {
			r_strbuf_append (sb, " ");
		} else if (*p >= 0x20 && *p < 0x7f) {
			r_strbuf_append_n (sb, (const char *)p, 1);
		}
	}
	return r_strbuf_drain (sb);
}

static bool has_token_before(const char *s, const char *end, const char *token, const char **hit) {
	const char *best = NULL;
	for (const char *p = strstr (s, token); p && p < end; p = strstr (p + 1, token)) {
		best = p;
	}
	if (best) {
		*hit = best;
		return true;
	}
	return false;
}

static bool signature_uses_cxx_scope(const char *s) {
	return strstr (s, "::") || strstr (s, "class ") || strstr (s, "<") || strstr (s, ">");
}

static bool signature_is_c_compatible(const char *s) {
	return !signature_uses_cxx_scope (s) && !strchr (s, '&');
}

static bool signature_type_text_is_simple(const char *s) {
	static const char *unsupported[] = {
		"::", "<", ">", "`", "__int64", "enum ", "__m128", "__m256",
		"(__cdecl *)", "(__stdcall *)", "(__fastcall *)", "(__thiscall *)",
		")const", ") const"
	};
	for (size_t i = 0; i < R_ARRAY_SIZE (unsupported); i++) {
		if (strstr (s, unsupported[i])) {
			return false;
		}
	}
	return true;
}

typedef struct {
	char *ret;
	char *cc;
	char *qname;
	char *args;
	bool has_access;
	bool is_static;
} SigParts;

static char *trim_dup(const char *start, const char *end) {
	while (start < end && isspace ((unsigned char)*start)) {
		start++;
	}
	while (end > start && isspace ((unsigned char)end[-1])) {
		end--;
	}
	return r_str_ndup (start, (int)(end - start));
}

static void sig_parts_fini(SigParts *sp) {
	free (sp->ret);
	free (sp->cc);
	free (sp->qname);
	free (sp->args);
}

static bool parse_signature(const char *sig, SigParts *sp) {
	static const char * const calling_conventions[] = {
		"__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall"
	};
	const char *lparen = strchr (sig, '(');
	const char *cc = NULL;
	size_t cc_len = 0;
	static const char * const access[] = {
		"public virtual: ", "private virtual: ", "protected virtual: ",
		"public static: ", "private static: ", "protected static: ",
		"public: ", "private: ", "protected: "
	};
	const char *start = sig;
	if (!lparen || strstr (sig, "operator")) {
		return false;
	}
	for (size_t i = 0; i < R_ARRAY_SIZE (access); i++) {
		if (r_str_startswith (start, access[i])) {
			start += strlen (access[i]);
			sp->has_access = true;
			break;
		}
	}
	for (size_t i = 0; i < R_ARRAY_SIZE (calling_conventions); i++) {
		const char *hit = NULL;
		if (has_token_before (start, lparen, calling_conventions[i], &hit)) {
			cc = hit;
			cc_len = strlen (calling_conventions[i]);
			break;
		}
	}

	const char *name = NULL;
	const char *ret_end = start;
	if (cc) {
		ret_end = cc;
		const char *cc_end = cc + cc_len;
		name = cc_end;
		while (*name == ' ') {
			name++;
		}
		sp->cc = trim_dup (cc, cc_end);
	} else {
		const char *last_space = NULL;
		for (const char *p = start; p < lparen; p++) {
			if (*p == ' ') {
				last_space = p;
			}
		}
		if (!last_space) {
			return false;
		}
		ret_end = last_space;
		name = last_space + 1;
	}
	if (name >= lparen) {
		sig_parts_fini (sp);
		return false;
	}
	sp->ret = trim_dup (start, ret_end);
	if (sp->ret && r_str_startswith (sp->ret, "static ")) {
		char *ret = strdup (sp->ret + strlen ("static "));
		if (!ret) {
			sig_parts_fini (sp);
			return false;
		}
		free (sp->ret);
		sp->ret = ret;
		sp->is_static = true;
	}
	sp->qname = trim_dup (name, lparen);
	sp->args = strdup (lparen);
	if (!sp->ret || !sp->qname || !sp->args) {
		sig_parts_fini (sp);
		return false;
	}
	return true;
}

static bool is_simple_cxx_name(const char *s) {
	if (!is_c_ident (s)) {
		return false;
	}
	return strcmp (s, "class") && strcmp (s, "struct") && strcmp (s, "union");
}

static bool split_scope_component(const char **p, char **out) {
	const char *start = *p;
	const char *end = strstr (start, "::");
	if (!end) {
		end = start + strlen (start);
	}
	*out = trim_dup (start, end);
	if (!*out || !is_simple_cxx_name (*out)) {
		free (*out);
		*out = NULL;
		return false;
	}
	*p = *end? end + 2: end;
	return true;
}

static int cxx_scope_component_count(const char *s) {
	int n = 1;
	for (const char *p = strstr (s, "::"); p; p = strstr (p + 2, "::")) {
		n++;
	}
	return n;
}

static bool cxx_scope_has_known_namespace(const char *scope) {
	char *first = NULL;
	const char *p = scope;
	if (!split_scope_component (&p, &first)) {
		return false;
	}
	bool ok = islower ((unsigned char)first[0]) ||
		!strcmp (first, "ATL") ||
		!strcmp (first, "Concurrency") ||
		!strcmp (first, "Microsoft") ||
		!strcmp (first, "Windows");
	free (first);
	return ok;
}

static char *global_signature_typedef(SigParts *sp, ut64 key) {
	if (!sp->ret || !*sp->ret || !sp->qname || !*sp->qname) {
		return NULL;
	}
	if (!signature_type_text_is_simple (sp->ret) || !signature_type_text_is_simple (sp->args)) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	r_strbuf_appendf (sb, "typedef %s ", sp->ret);
	if (sp->cc) {
		r_strbuf_appendf (sb, "(%s *fid_%016"PFMT64x"_t)%s;", sp->cc, key, sp->args);
	} else {
		r_strbuf_appendf (sb, "(*fid_%016"PFMT64x"_t)%s;", key, sp->args);
	}
	return r_strbuf_drain (sb);
}

static char *scoped_function_declaration(SigParts *sp, ut64 key) {
	const char *sep = strrchr (sp->qname, ':');
	if (!sep || sep == sp->qname || sep[-1] != ':' || !sp->ret || !*sp->ret) {
		return NULL;
	}
	if (!signature_type_text_is_simple (sp->ret) || !signature_type_text_is_simple (sp->args)) {
		return NULL;
	}
	char *scope = trim_dup (sp->qname, sep - 1);
	const char *leaf = sep + 1;
	if (!scope || !is_simple_cxx_name (leaf)) {
		free (scope);
		return NULL;
	}
	if (cxx_scope_component_count (scope) > 2) {
		free (scope);
		return NULL;
	}
	if (!cxx_scope_has_known_namespace (scope)) {
		free (scope);
		return NULL;
	}
	free (scope);
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	r_strbuf_appendf (sb, "typedef %s ", sp->ret);
	if (sp->cc) {
		r_strbuf_appendf (sb, "(%s *fid_%016"PFMT64x"_t)%s; /* %s */", sp->cc, key, sp->args, sp->qname);
	} else {
		r_strbuf_appendf (sb, "(*fid_%016"PFMT64x"_t)%s; /* %s */", key, sp->args, sp->qname);
	}
	return r_strbuf_drain (sb);
}

static char *member_function_typedef(SigParts *sp, ut64 key) {
	const char *sep = strrchr (sp->qname, ':');
	if (!sep || sep == sp->qname || sep[-1] != ':' || !sp->ret || !*sp->ret) {
		return NULL;
	}
	if (!signature_type_text_is_simple (sp->ret) || !signature_type_text_is_simple (sp->args)) {
		return NULL;
	}
	char *classq = trim_dup (sp->qname, sep - 1);
	if (!classq || strstr (classq, "<") || strstr (classq, ">") || strstr (classq, "`")) {
		free (classq);
		return NULL;
	}
	if (cxx_scope_component_count (classq) > 2) {
		free (classq);
		return NULL;
	}
	const char *class_sep = strrchr (classq, ':');
	const char *class_name = class_sep? class_sep + 1: classq;
	if (!is_simple_cxx_name (class_name)) {
		free (classq);
		return NULL;
	}
	if (class_sep) {
		char *scope = trim_dup (classq, class_sep - 1);
		bool ok = scope && cxx_scope_has_known_namespace (scope);
		free (scope);
		if (!ok) {
			free (classq);
			return NULL;
		}
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		free (classq);
		return NULL;
	}
	r_strbuf_appendf (sb, "typedef %s (", sp->ret);
	if (sp->cc) {
		r_strbuf_appendf (sb, "%s ", sp->cc);
	}
	r_strbuf_appendf (sb, "%s::*fid_%016"PFMT64x"_t)%s;", classq, key, sp->args);
	free (classq);
	return r_strbuf_drain (sb);
}

static char *signature_declaration(const char *sig, ut64 key, bool *cxx_only, bool *needs_cxx_types) {
	SigParts sp = {0};
	if (!parse_signature (sig, &sp)) {
		return NULL;
	}
	char *decl = NULL;
	if (strstr (sp.qname, "::")) {
		if (sp.is_static) {
			decl = global_signature_typedef (&sp, key);
		} else if (sp.has_access || (sp.cc && !strcmp (sp.cc, "__thiscall"))) {
			decl = member_function_typedef (&sp, key);
			*needs_cxx_types = decl != NULL;
		} else {
			decl = scoped_function_declaration (&sp, key);
		}
		*cxx_only = true;
	} else {
		decl = global_signature_typedef (&sp, key);
		*cxx_only = !signature_is_c_compatible (sig);
	}
	sig_parts_fini (&sp);
	return decl;
}

static char *function_signature(const char *name) {
	if (R_STR_ISEMPTY (name) || name[0] != '?') {
		return NULL;
	}
	return r_bin_demangle_msvc (name);
}

static void print_c_header(FidDb *db, int limit, bool emit_fid_types) {
	int n = function_limit (db, limit);
	printf ("/* Generated from Ghidra FID raw database (.fidbf).\n");
	printf (" * This header emits compiler-readable declarations when a symbol name carries\n");
	printf (" * enough type information to recover one. C++ scoped names keep their ::\n");
	printf (" * spelling in comments.\n");
	printf (" * FID records do not store undecorated C prototypes, struct layouts, or raw\n");
	printf (" * byte patterns.\n");
	printf (" * Use -f to also emit synthetic fid_* function-pointer typedefs.\n");
	printf (" */\n\n");
	printf ("#ifndef GHIDRA_FIDB_SIGNATURES_H\n");
	printf ("#define GHIDRA_FIDB_SIGNATURES_H\n\n");
	printf ("#include <stdbool.h>\n");
	printf ("#include <stddef.h>\n\n");
	printf ("#if !defined(_MSC_VER) && !defined(__cdecl)\n");
	printf ("#define __cdecl\n");
	printf ("#endif\n");
	printf ("#if !defined(_MSC_VER) && !defined(__stdcall)\n");
	printf ("#define __stdcall\n");
	printf ("#endif\n");
	printf ("#if !defined(_MSC_VER) && !defined(__fastcall)\n");
	printf ("#define __fastcall\n");
	printf ("#endif\n");
	printf ("#if !defined(_MSC_VER) && !defined(__thiscall)\n");
	printf ("#define __thiscall\n");
	printf ("#endif\n");
	printf ("#if !defined(_MSC_VER) && !defined(__vectorcall)\n");
	printf ("#define __vectorcall\n");
	printf ("#endif\n\n");
	for (int i = 0; i < n; i++) {
		FunctionRec *f = &db->functions.v[i];
		const char *name0 = string_lookup (&db->strings, f->name_id);
		const char *path0 = string_lookup (&db->strings, f->domain_path_id);
		LibraryRec *l = library_lookup (&db->libraries, f->library_id);
		char *name = c_comment (name0);
		char *path = c_comment (path0);
		char *family = c_comment (l && l->family? l->family: "");
		char *version = c_comment (l && l->version? l->version: "");
		char *variant = c_comment (l && l->variant? l->variant: "");
		char *sig0 = function_signature (name0);
		char *sig = c_comment (sig0? sig0: "unavailable");
		bool cxx_only = false;
		bool needs_cxx_types = false;
		char *decl = sig0? signature_declaration (sig0, f->key, &cxx_only, &needs_cxx_types): NULL;
		printf ("/* fidb: fid=0x%016"PFMT64x" full_hash=0x%016"PFMT64x" specific_hash=0x%016"PFMT64x" code_unit_size=%u specific_hash_additional_size=%u entry=0x%016"PFMT64x" flags=0x%02x library=\"%s %s %s\" name=\"%s\" signature=\"%s\" path=\"%s\" */\n",
			f->key, f->full_hash, f->specific_hash, f->code_unit_size,
			f->specific_hash_additional_size, f->entry_point, f->flags,
			family? family: "", version? version: "", variant? variant: "",
			name? name: "", sig? sig: "", path? path: "");
		if (emit_fid_types && decl) {
			if (cxx_only) {
				if (needs_cxx_types) {
					printf ("#if defined(__cplusplus) && defined(GHIDRA_FIDB_DECLARE_CXX_MEMBERS)\n%s\n#endif\n", decl);
				} else {
					printf ("#ifdef __cplusplus\n%s\n#endif\n", decl);
				}
			} else {
				printf ("%s\n", decl);
			}
		}
		free (name);
		free (path);
		free (family);
		free (version);
		free (variant);
		free (sig0);
		free (sig);
		free (decl);
	}
	printf ("\n#endif /* GHIDRA_FIDB_SIGNATURES_H */\n");
}

static void print_r2_script(FidDb *db, int limit) {
	int n = function_limit (db, limit);
	printf ("# Generated from Ghidra FID raw database (.fidbf)\n");
	printf ("# NOTE: Ghidra FID full/specific hashes are recorded as metadata comments.\n");
	printf ("# radare2 zignatures do not currently match on these 64-bit Ghidra FID hashes directly.\n");
	printf ("zs+ghidra.fid\n");
	for (int i = 0; i < n; i++) {
		FunctionRec *f = &db->functions.v[i];
		const char *name0 = string_lookup (&db->strings, f->name_id);
		const char *path0 = string_lookup (&db->strings, f->domain_path_id);
		LibraryRec *l = library_lookup (&db->libraries, f->library_id);
		char *name = clean_line (name0);
		char *path = clean_line (path0);
		char *zn = zigname_for (name, f->key);
		if (!name || !path || !zn) {
			free (name);
			free (path);
			free (zn);
			continue;
		}
		char *name64 = r_base64_encode_dyn ((const ut8 *)name, -1);
		if (!name64) {
			free (name);
			free (path);
			free (zn);
			continue;
		}
		printf ("za %s R %s\n", zn, name64);
		printf ("za %s o 0x%016"PFMT64x"\n", zn, f->entry_point);
		printf ("za %s c ghidra_fid function_id=0x%016"PFMT64x" full_hash=0x%016"PFMT64x" specific_hash=0x%016"PFMT64x" code_unit_size=%u specific_hash_additional_size=%u flags=0x%02x library=\"%s %s %s\" path=\"%s\"\n",
			zn, f->key, f->full_hash, f->specific_hash, f->code_unit_size,
			f->specific_hash_additional_size, f->flags,
			l && l->family? l->family: "", l && l->version? l->version: "",
			l && l->variant? l->variant: "", path);
		free (name);
		free (name64);
		free (path);
		free (zn);
	}
}

static void usage(const char *argv0) {
	printf ("Usage: %s [-r|-F|-c] [-f] [-n limit] file.fidbf\n", argv0);
	printf ("  -r        emit an r2 script with za/zs commands\n");
	printf ("  -F        enumerate functions as TSV\n");
	printf ("  -c        emit a compiler-readable .h with recovered signatures and FID comments\n");
	printf ("  -f        with -c, also emit synthetic fid_* function-pointer typedefs\n");
	printf ("  -n limit  limit emitted/listed functions (0 means all; summary default is 20)\n");
}

int main(int argc, char **argv) {
	bool emit_r2 = false;
	bool emit_tsv = false;
	bool emit_c = false;
	bool emit_fid_types = false;
	int limit = -1;
	RGetopt opt;
	int c;

	r_getopt_init (&opt, argc, (const char **)argv, "rFcfhn:");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'r':
			emit_r2 = true;
			break;
		case 'F':
			emit_tsv = true;
			break;
		case 'c':
			emit_c = true;
			break;
		case 'f':
			emit_fid_types = true;
			break;
		case 'n':
			limit = atoi (opt.arg);
			break;
		case 'h':
		case 0:
			usage (argv[0]);
			return 0;
		default:
			usage (argv[0]);
			return 1;
		}
	}
	if (opt.ind + 1 != argc) {
		usage (argv[0]);
		return 1;
	}
	const char *file = argv[opt.ind];
	FidFile ff = {0};
	FidDb db = {0};
	if (!fid_load_file (file, &ff)) {
		eprintf ("Cannot open or recognize %s as a Ghidra raw buffer database\n", file);
		return 1;
	}
	bool ok = fid_parse (&ff, &db);
	if (!ok) {
		eprintf ("Failed to parse FID database tables from %s\n", file);
		free (ff.buf);
		fid_db_fini (&db);
		return 1;
	}
	if (emit_r2) {
		print_r2_script (&db, limit);
	} else if (emit_tsv) {
		print_tsv (&db, limit);
	} else if (emit_c) {
		print_c_header (&db, limit, emit_fid_types);
	} else {
		printf ("File: %s\n", file);
		printf ("Block size: %d bytes, user buffer size: %d bytes\n", ff.block_size, ff.buffer_size);
		printf ("Counts: tables=%d libraries=%d strings=%d functions=%d inferior_relations=%d superior_relations=%d\n",
			db.tables.n, db.libraries.n, db.strings.n, db.functions.n, db.inferior_relations, db.superior_relations);
		print_tables (&db);
		print_libraries (&db);
		print_functions (&db, limit >= 0? limit: 20);
	}
	fid_db_fini (&db);
	free (ff.buf);
	return 0;
}
