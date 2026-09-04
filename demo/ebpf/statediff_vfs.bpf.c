#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "statediff_vfs.h"

#define S_IFMT 00170000
#define S_IFDIR 0040000
#define S_IFREG 0100000

#define FMODE_CREATED 0x100000

#define IOCB_CMD_PWRITE 1
#define IOCB_CMD_PWRITEV 8

#define IOCB_WRITE (1 << 18)

#define PROT_WRITE 0x2
#define MAP_SHARED 0x01
#define MAP_SHARED_VALIDATE 0x03
#define MAP_TYPE 0x0f

#define FALLOC_FL_KEEP_SIZE 0x01
#define FALLOC_FL_PUNCH_HOLE 0x02
#define FALLOC_FL_ZERO_RANGE 0x10

#define PAGE_SHIFT 12
#define PG_head 6

#define PAGE_MAPPING_FLAGS 0x3

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline long read_user_chunk(struct statediff_vfs_event_storage *storage,
					    unsigned long long len,
					    const void *src)
{
	long chunk = (long)len;

	if (chunk <= 0 || chunk > STATEDIFF_VFS_MAX_WRITE_DATA_LEN)
		return -1;

	barrier_var(chunk);

	return bpf_probe_read_user(storage->data, chunk, src);
}

#define STATEDIFF_VFS_MAX_IOV_SEGS 1024

struct statediff_vfs_pending {
	unsigned int op;
	unsigned int mode;
	unsigned int flags;
	unsigned long long offset;
	unsigned long long size;
	const char *buf;
	unsigned int is_dir;
	struct statediff_vfs_inode_key parent;
	struct statediff_vfs_inode_key object;
	struct statediff_vfs_inode_key new_parent;
	struct statediff_vfs_inode_key new_object;
	char name[STATEDIFF_VFS_NAME_LEN];
	char new_name[STATEDIFF_VFS_NAME_LEN];
	unsigned long long iov_ptr;
	unsigned long long pos_ptr;
	unsigned int iov_segs;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct statediff_vfs_inode_key);
	__type(value, unsigned char);
} tracked_dirs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, struct statediff_vfs_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned long long);
	__type(value, struct statediff_vfs_pending);
} pending_mkdir SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned long long);
	__type(value, struct statediff_vfs_pending);
} pending_write SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned long long);
	__type(value, struct statediff_vfs_pending);
} pending_truncate SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned long long);
	__type(value, struct statediff_vfs_pending);
} pending_fallocate SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned long long);
	__type(value, struct statediff_vfs_pending);
} pending_unlink SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned long long);
	__type(value, struct statediff_vfs_pending);
} pending_rmdir SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned long long);
	__type(value, struct statediff_vfs_pending);
} pending_rename SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned long long);
	__type(value, struct statediff_vfs_pending);
} pending_writev SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, struct statediff_vfs_pending);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, struct statediff_vfs_event_storage);
} event_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct statediff_vfs_inode_key);
	__type(value, unsigned char);
} mmap_files SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned long long);
	__type(value, unsigned char);
} dio_inflight SEC(".maps");

const volatile unsigned int ignored_pid = 0;

static __always_inline void count_stat(unsigned int field,
				       unsigned long long value)
{
	unsigned int key = 0;
	struct statediff_vfs_stats *s;

	s = bpf_map_lookup_elem(&stats, &key);
	if (!s)
		return;

	if (field == 0)
		__sync_fetch_and_add(&s->create_enter, value);
	else if (field == 1)
		__sync_fetch_and_add(&s->mkdir_enter, value);
	else if (field == 2)
		__sync_fetch_and_add(&s->write_enter, value);
	else if (field == 3)
		__sync_fetch_and_add(&s->truncate_enter, value);
	else if (field == 4)
		__sync_fetch_and_add(&s->unlink_enter, value);
	else if (field == 5)
		__sync_fetch_and_add(&s->rmdir_enter, value);
	else if (field == 6)
		__sync_fetch_and_add(&s->rename_enter, value);
	else if (field == 8)
		__sync_fetch_and_add(&s->parent_untracked, value);
	else if (field == 9)
		__sync_fetch_and_add(&s->name_read_fail, value);
	else if (field == 10)
		__sync_fetch_and_add(&s->events_submitted, value);
	else if (field == 11)
		__sync_fetch_and_add(&s->ringbuf_drops, value);
	else if (field == 12)
		__sync_fetch_and_add(&s->write_bytes_dropped, value);
	else if (field == 13)
		__sync_fetch_and_add(&s->write_chunks_dropped, value);
	else if (field == 14)
		__sync_fetch_and_add(&s->probe_read_failures, value);
	else if (field == 15)
		__sync_fetch_and_add(&s->dio_submit_enter, value);
	else if (field == 16)
		__sync_fetch_and_add(&s->dio_complete_enter, value);
	else if (field == 17)
		__sync_fetch_and_add(&s->dio_iocb_read_failures, value);
	else if (field == 18)
		__sync_fetch_and_add(&s->dio_iovec_read_failures, value);
	else if (field == 19)
		__sync_fetch_and_add(&s->dio_payload_read_failures, value);
	else if (field == 20)
		__sync_fetch_and_add(&s->fallocate_unsupported, value);
}

static __always_inline void record_untracked_parent(
	unsigned int op, const struct statediff_vfs_inode_key *key)
{
	unsigned int map_key = 0;
	struct statediff_vfs_stats *s;

	count_stat(8, 1);
	s = bpf_map_lookup_elem(&stats, &map_key);
	if (!s)
		return;
	s->last_untracked_dev = key->dev;
	s->last_untracked_ino = key->ino;
	s->last_untracked_op = op;
}

static __always_inline void count_enter(unsigned int op)
{
	if (op == SD_VFS_OP_CREATE)
		count_stat(0, 1);
	else if (op == SD_VFS_OP_MKDIR)
		count_stat(1, 1);
	else if (op == SD_VFS_OP_WRITE)
		count_stat(2, 1);
	else if (op == SD_VFS_OP_TRUNCATE)
		count_stat(3, 1);
	else if (op == SD_VFS_OP_UNLINK)
		count_stat(4, 1);
	else if (op == SD_VFS_OP_RMDIR)
		count_stat(5, 1);
	else if (op == SD_VFS_OP_RENAME)
		count_stat(6, 1);
}

static __always_inline unsigned long long current_key(void)
{
	return bpf_get_current_pid_tgid();
}

static __always_inline int filtered_out(void)
{
	unsigned long long pid_tgid = bpf_get_current_pid_tgid();

	if (ignored_pid && (unsigned int)(pid_tgid >> 32) == ignored_pid)
		return 1;
	return 0;
}

static __always_inline void init_pending(struct statediff_vfs_pending *p,
					 unsigned int op)
{
	p->op = op;
	p->mode = 0;
	p->flags = 0;
	p->offset = 0;
	p->size = 0;
	p->buf = 0;
	p->is_dir = 0;
	p->iov_ptr = 0;
	p->pos_ptr = 0;
	p->iov_segs = 0;
	p->parent.dev = 0;
	p->parent.ino = 0;
	p->object.dev = 0;
	p->object.ino = 0;
	p->new_parent.dev = 0;
	p->new_parent.ino = 0;
	p->new_object.dev = 0;
	p->new_object.ino = 0;
	p->name[0] = '\0';
	p->new_name[0] = '\0';
}

static __always_inline struct statediff_vfs_pending *get_scratch(unsigned int op)
{
	unsigned int key = 0;
	struct statediff_vfs_pending *p;

	p = bpf_map_lookup_elem(&scratch, &key);
	if (!p)
		return 0;
	init_pending(p, op);
	return p;
}

static __always_inline int inode_to_key(struct inode *inode,
					struct statediff_vfs_inode_key *key)
{
	struct super_block *sb;

	if (!inode)
		return 0;

	sb = BPF_CORE_READ(inode, i_sb);
	if (!sb)
		return 0;

	key->ino = BPF_CORE_READ(inode, i_ino);
	key->dev = BPF_CORE_READ(sb, s_dev);
	return key->ino != 0;
}

static __always_inline int dentry_to_key(struct dentry *dentry,
					 struct statediff_vfs_inode_key *key)
{
	struct inode *inode;

	if (!dentry)
		return 0;
	inode = BPF_CORE_READ(dentry, d_inode);
	return inode_to_key(inode, key);
}

static __always_inline int dentry_parent_key(struct dentry *dentry,
					     struct statediff_vfs_inode_key *key)
{
	struct dentry *parent;

	if (!dentry)
		return 0;
	parent = BPF_CORE_READ(dentry, d_parent);
	if (!parent)
		return 0;
	return dentry_to_key(parent, key);
}

static __always_inline int inode_is_dir(struct inode *inode)
{
	umode_t mode;

	if (!inode)
		return 0;
	mode = BPF_CORE_READ(inode, i_mode);
	return (mode & S_IFMT) == S_IFDIR;
}

static __always_inline int dentry_is_dir(struct dentry *dentry)
{
	struct inode *inode;

	if (!dentry)
		return 0;
	inode = BPF_CORE_READ(dentry, d_inode);
	return inode_is_dir(inode);
}

static __always_inline int dir_is_tracked(const struct statediff_vfs_inode_key *key)
{
	void *tracked;

	tracked = bpf_map_lookup_elem(&tracked_dirs, key);
	if (tracked)
		return 1;
	return 0;
}

static __always_inline int read_dentry_name(struct dentry *dentry, char *name)
{
	struct qstr q = {};
	long n;

	if (!dentry)
		return 0;

	BPF_CORE_READ_INTO(&q, dentry, d_name);
	if (!q.name || !q.len || q.len >= STATEDIFF_VFS_NAME_LEN)
		return 0;

	n = bpf_probe_read_kernel_str(name, STATEDIFF_VFS_NAME_LEN, q.name);
	return n > 1 && n <= STATEDIFF_VFS_NAME_LEN;
}

static __always_inline void fill_common(struct statediff_vfs_event *e,
					const struct statediff_vfs_pending *p,
					long long ret)
{
	unsigned long long pid_tgid = bpf_get_current_pid_tgid();
	unsigned long long uid_gid = bpf_get_current_uid_gid();

	e->op = p->op;
	e->pid = pid_tgid >> 32;
	e->tid = (unsigned int)pid_tgid;
	e->uid = (unsigned int)uid_gid;
	e->gid = uid_gid >> 32;
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->ret = ret;
	e->mode = p->mode;
	e->flags = p->flags;
	e->offset = p->offset;
	e->size = p->size;
	e->cookie = 0;
	e->is_dir = p->is_dir;
	e->data_len = 0;
	e->parent = p->parent;
	e->object = p->object;
	e->new_parent = p->new_parent;
	e->new_object = p->new_object;
	__builtin_memcpy(e->name, p->name, sizeof(e->name));
	__builtin_memcpy(e->new_name, p->new_name, sizeof(e->new_name));
}

static __always_inline struct statediff_vfs_event *reserve_empty_event(void)
{
	return bpf_ringbuf_reserve(&rb, STATEDIFF_VFS_EVENT_HEADER_LEN, 0);
}

static __always_inline struct statediff_vfs_event_storage *get_event_scratch(void)
{
	unsigned int key = bpf_get_smp_processor_id();

	return bpf_map_lookup_elem(&event_scratch, &key);
}

static __always_inline int emit_pending_event(void *map, long long ret)
{
	unsigned long long key = current_key();
	struct statediff_vfs_pending *p;
	struct statediff_vfs_event *e;

	p = bpf_map_lookup_elem(map, &key);
	if (!p)
		return 0;

	if (ret < 0) {
		bpf_map_delete_elem(map, &key);
		return 0;
	}

	e = reserve_empty_event();
	if (!e) {
		count_stat(11, 1);
		bpf_map_delete_elem(map, &key);
		return 0;
	}

	fill_common(e, p, ret);
	bpf_map_delete_elem(map, &key);
	count_stat(10, 1);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int save_child_op(void *map, unsigned int op,
					 struct inode *dir,
					 struct dentry *dentry,
					 unsigned int mode)
{
	unsigned long long key = current_key();
	struct statediff_vfs_pending *p;

	count_enter(op);
	if (filtered_out())
		return 0;

	p = get_scratch(op);
	if (!p)
		return 0;
	if (!inode_to_key(dir, &p->parent))
		return 0;
	if (!dir_is_tracked(&p->parent)) {
		record_untracked_parent(op, &p->parent);
		return 0;
	}
	if (!read_dentry_name(dentry, p->name)) {
		count_stat(9, 1);
		return 0;
	}

	p->mode = mode;
	dentry_to_key(dentry, &p->object);
	p->is_dir = op == SD_VFS_OP_MKDIR || op == SD_VFS_OP_RMDIR ||
		dentry_is_dir(dentry);

	bpf_map_update_elem(map, &key, p, BPF_ANY);
	return 0;
}

SEC("fexit/do_filp_open")
int BPF_PROG(handle_do_filp_open, int dfd, void *pathname, void *op,
	     struct file *file)
{
	struct statediff_vfs_pending *p;
	struct statediff_vfs_event *e;
	struct dentry *dentry;
	struct inode *inode;
	unsigned int fmode;
	unsigned long fp = (unsigned long)file;

	if (fp == 0 || fp >= (unsigned long)-4095L)
		return 0;

	fmode = BPF_CORE_READ(file, f_mode);
	if (!(fmode & FMODE_CREATED))
		return 0;

	count_enter(SD_VFS_OP_CREATE);
	if (filtered_out())
		return 0;

	p = get_scratch(SD_VFS_OP_CREATE);
	if (!p)
		return 0;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry_parent_key(dentry, &p->parent))
		return 0;
	if (!dir_is_tracked(&p->parent)) {
		record_untracked_parent(SD_VFS_OP_CREATE, &p->parent);
		return 0;
	}
	if (!read_dentry_name(dentry, p->name)) {
		count_stat(9, 1);
		return 0;
	}

	inode = BPF_CORE_READ(dentry, d_inode);
	inode_to_key(inode, &p->object);
	p->mode = BPF_CORE_READ(inode, i_mode);
	p->is_dir = inode_is_dir(inode);

	e = reserve_empty_event();
	if (!e)
		return 0;
	fill_common(e, p, 0);
	count_stat(10, 1);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/vfs_mkdir")
int BPF_PROG(handle_vfs_mkdir, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode)
{
	return save_child_op(&pending_mkdir, SD_VFS_OP_MKDIR, dir, dentry, mode);
}

SEC("fexit/vfs_mkdir")
int BPF_PROG(handle_vfs_mkdir_ret, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, int ret)
{
	struct statediff_vfs_pending *p;
	unsigned long long key = current_key();
	unsigned char tracked = 1;

	p = bpf_map_lookup_elem(&pending_mkdir, &key);
	if (p && ret >= 0 && dentry_to_key(dentry, &p->object))
		bpf_map_update_elem(&tracked_dirs, &p->object, &tracked, BPF_ANY);
	return emit_pending_event(&pending_mkdir, ret);
}

SEC("fentry/vfs_write")
int BPF_PROG(handle_vfs_write, struct file *file, const char *buf,
	     size_t count, loff_t *pos)
{
	unsigned long long key = current_key();
	struct statediff_vfs_pending *p;
	struct dentry *dentry;
	loff_t offset = 0;

	count_enter(SD_VFS_OP_WRITE);
	if (filtered_out() || !file)
		return 0;

	p = get_scratch(SD_VFS_OP_WRITE);
	if (!p)
		return 0;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry_parent_key(dentry, &p->parent))
		return 0;
	if (!dir_is_tracked(&p->parent)) {
		record_untracked_parent(SD_VFS_OP_WRITE, &p->parent);
		return 0;
	}
	if (!dentry_to_key(dentry, &p->object))
		return 0;
	if (!read_dentry_name(dentry, p->name)) {
		count_stat(9, 1);
		return 0;
	}

	if (pos)
		bpf_probe_read_kernel(&offset, sizeof(offset), pos);

	p->offset = offset;
	p->size = count;
	p->buf = buf;
	bpf_map_update_elem(&pending_write, &key, p, BPF_ANY);
	return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(handle_vfs_write_ret, struct file *file, const char *buf,
	     size_t count, loff_t *pos, ssize_t ret)
{
	struct statediff_vfs_pending *p;
	struct statediff_vfs_event_storage *storage;
	unsigned long long key = current_key();
	struct statediff_vfs_event *e;
	unsigned long long written;
	unsigned long long emitted = 0;
	unsigned long long next_emitted;
	unsigned long long start_offset;
	loff_t end_offset = 0;
	unsigned int data_len;
	int i;

	p = bpf_map_lookup_elem(&pending_write, &key);
	if (!p)
		return 0;
	if (ret <= 0) {
		bpf_map_delete_elem(&pending_write, &key);
		return 0;
	}

	written = (unsigned long long)ret;
	start_offset = p->offset;
	if (pos &&
	    bpf_probe_read_kernel(&end_offset, sizeof(end_offset), pos) == 0 &&
	    end_offset >= ret)
		start_offset = (unsigned long long)(end_offset - ret);

	for (i = 0; i < STATEDIFF_VFS_MAX_WRITE_CHUNKS; i++) {
		if (emitted >= written)
			break;

		if (written - emitted > STATEDIFF_VFS_MAX_WRITE_DATA_LEN)
			data_len = STATEDIFF_VFS_MAX_WRITE_DATA_LEN;
		else
			data_len = (unsigned int)(written - emitted);

		if (!data_len ||
		    data_len > STATEDIFF_VFS_MAX_WRITE_DATA_LEN) {
			count_stat(12, written - emitted);
			count_stat(13, 1);
			bpf_map_delete_elem(&pending_write, &key);
			return 0;
		}

		storage = get_event_scratch();
		if (!storage) {
			count_stat(12, written - emitted);
			count_stat(13, 1);
			bpf_map_delete_elem(&pending_write, &key);
			return 0;
		}
		e = (struct statediff_vfs_event *)storage;

		if (read_user_chunk(storage, data_len, p->buf + emitted) < 0) {
			count_stat(12, data_len);
			count_stat(13, 1);
			count_stat(14, 1);
			bpf_map_delete_elem(&pending_write, &key);
			return 0;
		}

		fill_common(e, p, data_len);
		e->offset = start_offset + emitted;
		e->size = data_len;
		e->data_len = data_len;
		next_emitted = emitted + data_len;
		if (next_emitted < written &&
		    i == STATEDIFF_VFS_MAX_WRITE_CHUNKS - 1)
			e->flags |= SD_VFS_EVENT_F_TRUNCATED;

		if (bpf_ringbuf_output(&rb, storage,
				       STATEDIFF_VFS_EVENT_HEADER_LEN + data_len,
				       0) < 0) {
			count_stat(11, 1);
			count_stat(12, written - emitted);
			count_stat(13, 1);
			bpf_map_delete_elem(&pending_write, &key);
			return 0;
		}
		count_stat(10, 1);
		emitted = next_emitted;
	}

	if (emitted < written) {
		count_stat(12, written - emitted);
		count_stat(13, 1);
	}
	bpf_map_delete_elem(&pending_write, &key);
	return 0;
}

SEC("kprobe/vfs_writev")
int BPF_KPROBE(handle_vfs_writev, struct file *file, const struct iovec *vec,
	       unsigned long vlen, loff_t *pos)
{
	unsigned long long key = current_key();
	struct statediff_vfs_pending *p;
	struct dentry *dentry;
	loff_t offset = 0;

	count_enter(SD_VFS_OP_WRITE);
	if (filtered_out() || !file || !vec)
		return 0;

	p = get_scratch(SD_VFS_OP_WRITE);
	if (!p)
		return 0;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry_parent_key(dentry, &p->parent))
		return 0;
	if (!dir_is_tracked(&p->parent)) {
		record_untracked_parent(SD_VFS_OP_WRITE, &p->parent);
		return 0;
	}
	if (!dentry_to_key(dentry, &p->object))
		return 0;
	if (!read_dentry_name(dentry, p->name)) {
		count_stat(9, 1);
		return 0;
	}

	if (pos)
		bpf_probe_read_kernel(&offset, sizeof(offset), pos);
	p->offset = offset;
	p->pos_ptr = (unsigned long long)pos;
	p->iov_ptr = (unsigned long long)vec;
	p->iov_segs = vlen;

	bpf_map_update_elem(&pending_writev, &key, p, BPF_ANY);
	return 0;
}

struct writev_emit_ctx {
	unsigned long long key;
	unsigned long long emitted;
};

static long writev_emit_seg(unsigned int i, void *data)
{
	struct writev_emit_ctx *c = data;
	struct statediff_vfs_pending *p;
	struct statediff_vfs_event_storage *storage;
	struct statediff_vfs_event *e;
	const struct iovec *vec;
	struct iovec seg;
	unsigned long long base;
	unsigned long long seg_len;
	unsigned int chunk;
	int truncated;

	p = bpf_map_lookup_elem(&pending_writev, &c->key);
	if (!p)
		return 1;

	vec = (const struct iovec *)p->iov_ptr;
	if (bpf_probe_read_user(&seg, sizeof(seg), &vec[i]) < 0) {
		count_stat(14, 1);
		return 1;
	}

	base = (unsigned long long)seg.iov_base;
	seg_len = (unsigned long long)seg.iov_len;
	if (seg_len == 0)
		return 0;

	truncated = seg_len > STATEDIFF_VFS_MAX_WRITE_DATA_LEN;
	chunk = truncated ? STATEDIFF_VFS_MAX_WRITE_DATA_LEN :
		(unsigned int)seg_len;
	if (!chunk || chunk > STATEDIFF_VFS_MAX_WRITE_DATA_LEN)
		return 1;

	storage = get_event_scratch();
	if (!storage)
		return 1;
	e = (struct statediff_vfs_event *)storage;

	if (read_user_chunk(storage, chunk, (const void *)base) < 0) {
		count_stat(14, 1);
		return 1;
	}

	fill_common(e, p, chunk);
	e->offset = p->offset + c->emitted;
	e->size = chunk;
	e->data_len = chunk;
	if (truncated)
		e->flags |= SD_VFS_EVENT_F_TRUNCATED;

	if (bpf_ringbuf_output(&rb, storage,
			       STATEDIFF_VFS_EVENT_HEADER_LEN + chunk, 0) < 0) {
		count_stat(11, 1);
		return 1;
	}
	count_stat(10, 1);
	c->emitted += chunk;

	return truncated ? 1 : 0;
}

SEC("kretprobe/vfs_writev")
int BPF_KRETPROBE(handle_vfs_writev_ret, ssize_t ret)
{
	unsigned long long key = current_key();
	unsigned long long written;
	struct statediff_vfs_pending *p;
	struct writev_emit_ctx emit = {};
	unsigned int segs;

	p = bpf_map_lookup_elem(&pending_writev, &key);
	if (!p)
		return 0;
	if (ret <= 0) {
		bpf_map_delete_elem(&pending_writev, &key);
		return 0;
	}

	written = (unsigned long long)ret;
	segs = p->iov_segs;
	if (segs > STATEDIFF_VFS_MAX_IOV_SEGS)
		segs = STATEDIFF_VFS_MAX_IOV_SEGS;

	if (p->pos_ptr) {
		long long end_offset = 0;

		if (bpf_probe_read_kernel(&end_offset, sizeof(end_offset),
					  (void *)p->pos_ptr) == 0 &&
		    (unsigned long long)end_offset >= written)
			p->offset = (unsigned long long)end_offset - written;
	}

	emit.key = key;
	emit.emitted = 0;

	bpf_loop(segs, writev_emit_seg, &emit, 0);

	if (emit.emitted != written) {
		unsigned long long lost = emit.emitted > written ?
			emit.emitted - written : written - emit.emitted;

		count_stat(12, lost);
		count_stat(13, 1);
	}

	bpf_map_delete_elem(&pending_writev, &key);
	return 0;
}

SEC("fentry/do_truncate")
int BPF_PROG(handle_do_truncate, struct mnt_idmap *idmap, struct dentry *dentry,
	     loff_t length, unsigned int time_attrs, struct file *filp)
{
	unsigned long long key = current_key();
	struct statediff_vfs_pending *p;

	count_enter(SD_VFS_OP_TRUNCATE);
	if (filtered_out() || !dentry)
		return 0;

	p = get_scratch(SD_VFS_OP_TRUNCATE);
	if (!p)
		return 0;
	if (!dentry_parent_key(dentry, &p->parent))
		return 0;
	if (!dir_is_tracked(&p->parent)) {
		record_untracked_parent(SD_VFS_OP_TRUNCATE, &p->parent);
		return 0;
	}
	if (!dentry_to_key(dentry, &p->object))
		return 0;
	if (!read_dentry_name(dentry, p->name)) {
		count_stat(9, 1);
		return 0;
	}

	p->size = length;
	bpf_map_update_elem(&pending_truncate, &key, p, BPF_ANY);
	return 0;
}

SEC("fexit/do_truncate")
int BPF_PROG(handle_do_truncate_ret, struct mnt_idmap *idmap,
	     struct dentry *dentry, loff_t length, unsigned int time_attrs,
	     struct file *filp, int ret)
{
	return emit_pending_event(&pending_truncate, ret);
}

SEC("fentry/vfs_fallocate")
int BPF_PROG(handle_vfs_fallocate, struct file *file, int mode, loff_t offset,
	     loff_t len)
{
	unsigned long long key = current_key();
	struct statediff_vfs_pending *p;
	struct dentry *dentry;

	count_enter(SD_VFS_OP_TRUNCATE);
	if (filtered_out() || !file || mode == FALLOC_FL_KEEP_SIZE)
		return 0;

	p = get_scratch(SD_VFS_OP_TRUNCATE);
	if (!p)
		return 0;
	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry_parent_key(dentry, &p->parent))
		return 0;
	if (!dir_is_tracked(&p->parent)) {
		record_untracked_parent(SD_VFS_OP_TRUNCATE, &p->parent);
		return 0;
	}
	if (!dentry_to_key(dentry, &p->object))
		return 0;
	if (!read_dentry_name(dentry, p->name)) {
		count_stat(9, 1);
		return 0;
	}

	p->mode = (unsigned int)mode;
	p->offset = offset;
	p->size = len;
	if (bpf_map_update_elem(&pending_fallocate, &key, p, BPF_ANY) < 0)
		count_stat(13, 1);
	return 0;
}

SEC("fexit/vfs_fallocate")
int BPF_PROG(handle_vfs_fallocate_ret, struct file *file, int mode,
	     loff_t offset, loff_t len, int ret)
{
	unsigned long long key = current_key();
	struct statediff_vfs_pending *p;
	struct inode *inode;

	p = bpf_map_lookup_elem(&pending_fallocate, &key);
	if (!p)
		return 0;
	if (ret < 0) {
		bpf_map_delete_elem(&pending_fallocate, &key);
		return 0;
	}
	if (p->mode == FALLOC_FL_ZERO_RANGE ||
	    p->mode == (FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE) ||
	    p->mode == (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)) {
		p->op = SD_VFS_OP_ZERO_RANGE;
		p->flags = p->mode & FALLOC_FL_KEEP_SIZE ?
			SD_VFS_ZERO_RANGE_F_KEEP_SIZE : 0;
		p->mode = 0;
		return emit_pending_event(&pending_fallocate, ret);
	}
	if (p->mode != 0) {
		count_stat(20, 1);
		bpf_map_delete_elem(&pending_fallocate, &key);
		return 0;
	}

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode) {
		count_stat(13, 1);
		bpf_map_delete_elem(&pending_fallocate, &key);
		return 0;
	}
	p->mode = 0;
	p->offset = 0;
	p->size = BPF_CORE_READ(inode, i_size);
	return emit_pending_event(&pending_fallocate, ret);
}

SEC("fentry/vfs_unlink")
int BPF_PROG(handle_vfs_unlink, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, struct inode **delegated_inode)
{
	return save_child_op(&pending_unlink, SD_VFS_OP_UNLINK, dir, dentry, 0);
}

SEC("fexit/vfs_unlink")
int BPF_PROG(handle_vfs_unlink_ret, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, struct inode **delegated_inode, int ret)
{
	return emit_pending_event(&pending_unlink, ret);
}

SEC("fentry/vfs_rmdir")
int BPF_PROG(handle_vfs_rmdir, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry)
{
	return save_child_op(&pending_rmdir, SD_VFS_OP_RMDIR, dir, dentry, 0);
}

SEC("fexit/vfs_rmdir")
int BPF_PROG(handle_vfs_rmdir_ret, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, int ret)
{
	struct statediff_vfs_pending *p;
	unsigned long long key = current_key();

	p = bpf_map_lookup_elem(&pending_rmdir, &key);
	if (p && ret >= 0)
		bpf_map_delete_elem(&tracked_dirs, &p->object);
	return emit_pending_event(&pending_rmdir, ret);
}

SEC("fentry/vfs_rename")
int BPF_PROG(handle_vfs_rename, struct renamedata *rd)
{
	unsigned long long key = current_key();
	struct statediff_vfs_pending *p;
	struct inode *old_dir;
	struct inode *new_dir;
	struct dentry *old_dentry;
	struct dentry *new_dentry;
	int old_tracked;
	int new_tracked;

	count_enter(SD_VFS_OP_RENAME);
	if (filtered_out() || !rd)
		return 0;

	p = get_scratch(SD_VFS_OP_RENAME);
	if (!p)
		return 0;

	old_dir = BPF_CORE_READ(rd, old_dir);
	new_dir = BPF_CORE_READ(rd, new_dir);
	old_dentry = BPF_CORE_READ(rd, old_dentry);
	new_dentry = BPF_CORE_READ(rd, new_dentry);

	if (!inode_to_key(old_dir, &p->parent))
		return 0;
	if (!inode_to_key(new_dir, &p->new_parent))
		return 0;

	old_tracked = dir_is_tracked(&p->parent);
	if (!old_tracked) {
		new_tracked = dir_is_tracked(&p->new_parent);
		if (!new_tracked) {
			record_untracked_parent(SD_VFS_OP_RENAME,
					       &p->new_parent);
			return 0;
		}
	}

	if (!dentry_to_key(old_dentry, &p->object))
		return 0;
	p->new_object = p->object;
	p->is_dir = dentry_is_dir(old_dentry);
	p->flags = BPF_CORE_READ(rd, flags);
	if (!read_dentry_name(old_dentry, p->name)) {
		count_stat(9, 1);
		return 0;
	}
	if (!read_dentry_name(new_dentry, p->new_name)) {
		count_stat(9, 1);
		return 0;
	}

	bpf_map_update_elem(&pending_rename, &key, p, BPF_ANY);
	return 0;
}

SEC("fexit/vfs_rename")
int BPF_PROG(handle_vfs_rename_ret, struct renamedata *rd, int ret)
{
	struct statediff_vfs_pending *p;
	unsigned long long key = current_key();
	unsigned char tracked = 1;
	int old_tracked;
	int new_tracked;

	p = bpf_map_lookup_elem(&pending_rename, &key);
	if (!p)
		return 0;
	if (ret >= 0 && p->is_dir) {
		new_tracked = dir_is_tracked(&p->new_parent);
		if (new_tracked)
			bpf_map_update_elem(&tracked_dirs, &p->object, &tracked,
					    BPF_ANY);
		else {
			old_tracked = dir_is_tracked(&p->parent);
			if (old_tracked)
				bpf_map_delete_elem(&tracked_dirs, &p->object);
		}
	}
	return emit_pending_event(&pending_rename, ret);
}

SEC("fentry/security_mmap_file")
int BPF_PROG(handle_security_mmap_file, struct file *file, unsigned long prot,
	     unsigned long flags)
{
	struct statediff_vfs_pending *p;
	struct statediff_vfs_event *e;
	struct dentry *dentry;
	struct inode *inode;
	unsigned long mtype = flags & MAP_TYPE;
	unsigned char tracked = 1;
	umode_t mode;

	if (!file || !(prot & PROT_WRITE))
		return 0;
	if (mtype != MAP_SHARED && mtype != MAP_SHARED_VALIDATE)
		return 0;
	if (filtered_out())
		return 0;

	p = get_scratch(SD_VFS_OP_MMAP);
	if (!p)
		return 0;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry_parent_key(dentry, &p->parent))
		return 0;
	if (!dir_is_tracked(&p->parent)) {
		record_untracked_parent(SD_VFS_OP_MMAP, &p->parent);
		return 0;
	}

	inode = BPF_CORE_READ(dentry, d_inode);
	mode = BPF_CORE_READ(inode, i_mode);
	if ((mode & S_IFMT) != S_IFREG)
		return 0;
	if (!inode_to_key(inode, &p->object))
		return 0;
	if (!read_dentry_name(dentry, p->name)) {
		count_stat(9, 1);
		return 0;
	}

	bpf_map_update_elem(&mmap_files, &p->object, &tracked, BPF_ANY);

	e = reserve_empty_event();
	if (!e)
		return 0;
	fill_common(e, p, 0);
	count_stat(10, 1);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline unsigned long long folio_size_bytes(struct folio *folio)
{
	unsigned long flags = BPF_CORE_READ(folio, flags);

	if (flags & (1UL << PG_head)) {
		unsigned int nr = BPF_CORE_READ(folio, _folio_nr_pages);

		return (unsigned long long)nr << PAGE_SHIFT;
	}
	return 1ULL << PAGE_SHIFT;
}

SEC("fentry/__folio_start_writeback")
int BPF_PROG(handle_folio_start_writeback, struct folio *folio, bool keep_write)
{
	struct statediff_vfs_pending *p;
	struct statediff_vfs_event *e;
	struct address_space *mapping;
	struct inode *host;
	struct statediff_vfs_inode_key key = {};

	if (!folio)
		return 0;
	mapping = BPF_CORE_READ(folio, mapping);
	if (!mapping || ((unsigned long)mapping & PAGE_MAPPING_FLAGS))
		return 0;

	host = BPF_CORE_READ(mapping, host);
	if (!inode_to_key(host, &key))
		return 0;
	if (!bpf_map_lookup_elem(&mmap_files, &key))
		return 0;

	p = get_scratch(SD_VFS_OP_WRITEBACK);
	if (!p)
		return 0;
	p->object = key;
	p->offset = (unsigned long long)BPF_CORE_READ(folio, index) << PAGE_SHIFT;
	p->size = folio_size_bytes(folio);

	e = reserve_empty_event();
	if (!e) {
		count_stat(11, 1);
		return 0;
	}
	fill_common(e, p, 0);
	count_stat(10, 1);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline unsigned int dio_emit_one(struct statediff_vfs_pending *p,
						 unsigned long long cookie,
						 unsigned long long offset,
						 const void *base,
						 unsigned long long len)
{
	struct statediff_vfs_event_storage *storage;
	struct statediff_vfs_event *e;
	unsigned int chunk;
	int truncated;

	if (len == 0)
		return 0;
	truncated = len > STATEDIFF_VFS_MAX_WRITE_DATA_LEN;
	chunk = truncated ? STATEDIFF_VFS_MAX_WRITE_DATA_LEN : (unsigned int)len;
	if (!chunk || chunk > STATEDIFF_VFS_MAX_WRITE_DATA_LEN)
		return 0;

	storage = get_event_scratch();
	if (!storage)
		return 0;
	e = (struct statediff_vfs_event *)storage;

	if (read_user_chunk(storage, chunk, base) < 0) {
		count_stat(19, 1);
		return 0;
	}

	fill_common(e, p, chunk);
	e->cookie = cookie;
	e->offset = offset;
	e->size = chunk;
	e->data_len = chunk;
	if (truncated)
		e->flags |= SD_VFS_EVENT_F_TRUNCATED;

	if (bpf_ringbuf_output(&rb, storage,
			       STATEDIFF_VFS_EVENT_HEADER_LEN + chunk, 0) < 0) {
		count_stat(11, 1);
		return 0;
	}
	count_stat(10, 1);
	return chunk;
}

struct dio_seg_ctx {
	struct statediff_vfs_pending *p;
	const struct iovec *iov;
	unsigned long long cookie;
	unsigned long long pos;
	unsigned long long emitted;
	unsigned int failed;
};

static long dio_emit_seg(unsigned int i, void *data)
{
	struct dio_seg_ctx *c = data;
	struct iovec seg;
	unsigned long long seg_len;
	unsigned int got;

	if (bpf_probe_read_user(&seg, sizeof(seg), &c->iov[i]) < 0) {
		count_stat(18, 1);
		c->failed = 1;
		return 1;
	}
	seg_len = (unsigned long long)seg.iov_len;
	if (seg_len == 0)
		return 0;
	got = dio_emit_one(c->p, c->cookie, c->pos + c->emitted,
			   (const void *)seg.iov_base, seg_len);
	if (!got || (unsigned long long)got != seg_len) {
		c->failed = 1;
		return 1;
	}
	c->emitted += got;
	return 0;
}

static __always_inline int dio_emit_control(unsigned int op,
					    unsigned long long cookie,
					    long long ret,
					    unsigned long long size)
{
	struct statediff_vfs_event *e;
	unsigned long long pid_tgid = bpf_get_current_pid_tgid();

	e = reserve_empty_event();
	if (!e) {
		count_stat(11, 1);
		return -1;
	}
	__builtin_memset(e, 0, STATEDIFF_VFS_EVENT_HEADER_LEN);
	e->op = op;
	e->pid = pid_tgid >> 32;
	e->tid = (unsigned int)pid_tgid;
	e->ret = ret;
	e->cookie = cookie;
	e->size = size;
	count_stat(10, 1);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline void dio_emit_complete(struct kiocb *kiocb,
					      unsigned long long cookie,
					      long long res)
{
	struct statediff_vfs_inode_key parent = {};
	struct statediff_vfs_event *e;
	struct file *file;
	struct dentry *dentry;
	char name[STATEDIFF_VFS_NAME_LEN] = {};
	int have_name = 0;

	file = BPF_CORE_READ(kiocb, ki_filp);
	dentry = file ? BPF_CORE_READ(file, f_path.dentry) : 0;
	if (dentry && dentry_parent_key(dentry, &parent) &&
	    dir_is_tracked(&parent))
		have_name = read_dentry_name(dentry, name);

	e = reserve_empty_event();
	if (!e) {
		count_stat(11, 1);
		return;
	}
	__builtin_memset(e, 0, STATEDIFF_VFS_EVENT_HEADER_LEN);
	e->op = SD_VFS_OP_DIO_COMPLETE;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ret = res;
	e->cookie = cookie;
	if (have_name) {
		e->parent = parent;
		__builtin_memcpy(e->name, name, sizeof(name));
	}
	count_stat(10, 1);
	bpf_ringbuf_submit(e, 0);
}

SEC("fentry/io_submit_one")
int BPF_PROG(handle_io_submit_one, struct kioctx *ioctx, struct iocb *user_iocb,
	     bool compat)
{
	unsigned char one = 1;
	unsigned long long cookie;

	if (filtered_out() || !user_iocb || compat)
		return 0;

	cookie = (unsigned long long)user_iocb;
	if (bpf_map_update_elem(&dio_inflight, &cookie, &one, BPF_ANY) < 0)
		count_stat(13, 1);
	return 0;
}

SEC("fexit/io_submit_one")
int BPF_PROG(handle_io_submit_one_exit, struct kioctx *ioctx,
	     struct iocb *user_iocb, bool compat, int ret)
{
	struct statediff_vfs_pending *p;
	struct iocb ib;
	unsigned long long cookie = (unsigned long long)user_iocb;
	unsigned long long emitted = 0;

	if (filtered_out() || !user_iocb || compat)
		return 0;
	if (ret < 0) {
		bpf_map_delete_elem(&dio_inflight, &cookie);
		return 0;
	}

	if (bpf_probe_read_user(&ib, sizeof(ib), user_iocb) < 0) {
		count_stat(17, 1);
		goto abort;
	}
	if (ib.aio_lio_opcode != IOCB_CMD_PWRITE &&
	    ib.aio_lio_opcode != IOCB_CMD_PWRITEV) {
		bpf_map_delete_elem(&dio_inflight, &cookie);
		return 0;
	}

	count_stat(15, 1);
	p = get_scratch(SD_VFS_OP_DIO_SUBMIT);
	if (!p) {
		count_stat(13, 1);
		goto abort;
	}
	p->offset = ib.aio_offset;

	if (ib.aio_lio_opcode == IOCB_CMD_PWRITE) {
		unsigned int got = 0;

		if (ib.aio_nbytes)
			got = dio_emit_one(p, cookie, ib.aio_offset,
					   (const void *)ib.aio_buf,
					   ib.aio_nbytes);
		if ((unsigned long long)got != ib.aio_nbytes)
			goto abort;
		emitted = got;
	} else {
		struct dio_seg_ctx c = {};
		unsigned int segs;
		long loop_ret;

		if (ib.aio_nbytes > STATEDIFF_VFS_MAX_IOV_SEGS) {
			count_stat(13, 1);
			goto abort;
		}
		segs = (unsigned int)ib.aio_nbytes;
		c.p = p;
		c.iov = (const struct iovec *)ib.aio_buf;
		c.cookie = cookie;
		c.pos = ib.aio_offset;
		loop_ret = bpf_loop(segs, dio_emit_seg, &c, 0);
		if (loop_ret < 0 || c.failed) {
			if (loop_ret < 0)
				count_stat(13, 1);
			goto abort;
		}
		emitted = c.emitted;
	}

	if (dio_emit_control(SD_VFS_OP_DIO_SUBMIT_DONE, cookie, 0,
			     emitted) < 0)
		bpf_map_delete_elem(&dio_inflight, &cookie);
	return 0;

abort:
	bpf_map_delete_elem(&dio_inflight, &cookie);
	dio_emit_control(SD_VFS_OP_DIO_ABORT, cookie, -1, emitted);
	return 0;
}

SEC("fentry/aio_complete_rw")
int BPF_PROG(handle_aio_complete_rw, struct kiocb *kiocb, long res)
{
	unsigned long long cookie;

	if (!kiocb)
		return 0;
	cookie = BPF_CORE_READ((struct aio_kiocb *)kiocb, ki_res.obj);
	if (!bpf_map_lookup_elem(&dio_inflight, &cookie))
		return 0;
	if (!(BPF_CORE_READ(kiocb, ki_flags) & IOCB_WRITE)) {
		bpf_map_delete_elem(&dio_inflight, &cookie);
		return 0;
	}
	bpf_map_delete_elem(&dio_inflight, &cookie);

	count_stat(16, 1);
	dio_emit_complete(kiocb, cookie, res);
	return 0;
}
