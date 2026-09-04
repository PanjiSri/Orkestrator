#ifndef __STATEDIFF_VFS_H
#define __STATEDIFF_VFS_H

#define STATEDIFF_VFS_NAME_LEN 256
#define STATEDIFF_VFS_MAX_WRITE_DATA_LEN (4 * 1024 * 1024)

#define STATEDIFF_VFS_MAX_WRITE_CHUNKS 8
#define STATEDIFF_VFS_MAGIC 0x31534656U
#define STATEDIFF_VFS_VERSION 1
#define STATEDIFF_VFS_DEFAULT_OUTPUT "statediff_vfs.sd"

#define STATEDIFF_VFS_SOCKET_GET 'g'
#define STATEDIFF_VFS_SOCKET_ERROR_SIZE (~0ULL)

#define SD_VFS_EVENT_F_TRUNCATED 0x0001
#define SD_VFS_ZERO_RANGE_F_KEEP_SIZE 0x0001

enum statediff_vfs_op {
	SD_VFS_OP_INVALID = 0,
	SD_VFS_OP_CREATE = 1,
	SD_VFS_OP_WRITE = 2,
	SD_VFS_OP_TRUNCATE = 3,
	SD_VFS_OP_UNLINK = 4,
	SD_VFS_OP_RENAME = 5,
	SD_VFS_OP_MKDIR = 6,
	SD_VFS_OP_RMDIR = 7,

	SD_VFS_OP_MMAP = 8,
	SD_VFS_OP_WRITEBACK = 9,

	SD_VFS_OP_DIO_SUBMIT = 10,
	SD_VFS_OP_DIO_COMPLETE = 11,
	SD_VFS_OP_DIO_SUBMIT_DONE = 12,
	SD_VFS_OP_DIO_ABORT = 13,

	SD_VFS_OP_ZERO_RANGE = 14,
};

struct statediff_vfs_inode_key {
	unsigned long long dev;
	unsigned long long ino;
};

#define STATEDIFF_VFS_EVENT_FIELDS \
	unsigned int op; \
	unsigned int pid; \
	unsigned int tid; \
	unsigned int uid; \
	unsigned int gid; \
	unsigned long long cgroup_id; \
	long long ret; \
	unsigned int mode; \
	unsigned int flags; \
	unsigned long long offset; \
	unsigned long long size; \
	unsigned long long cookie;  \
	unsigned int is_dir; \
	unsigned int data_len; \
	struct statediff_vfs_inode_key parent; \
	struct statediff_vfs_inode_key object; \
	struct statediff_vfs_inode_key new_parent; \
	struct statediff_vfs_inode_key new_object; \
	char name[STATEDIFF_VFS_NAME_LEN]; \
	char new_name[STATEDIFF_VFS_NAME_LEN];

struct statediff_vfs_event {
	STATEDIFF_VFS_EVENT_FIELDS
	char data[];
};

struct statediff_vfs_event_storage {
	STATEDIFF_VFS_EVENT_FIELDS
	char data[STATEDIFF_VFS_MAX_WRITE_DATA_LEN];
};

#define STATEDIFF_VFS_EVENT_HEADER_LEN \
	((unsigned int)__builtin_offsetof(struct statediff_vfs_event, data))

struct statediff_vfs_stats {
	unsigned long long create_enter;
	unsigned long long mkdir_enter;
	unsigned long long write_enter;
	unsigned long long truncate_enter;
	unsigned long long unlink_enter;
	unsigned long long rmdir_enter;
	unsigned long long rename_enter;
	unsigned long long dio_submit_enter;
	unsigned long long dio_complete_enter;
	unsigned long long cgroup_filtered;
	unsigned long long parent_untracked;
	unsigned long long name_read_fail;
	unsigned long long events_submitted;
	unsigned long long ringbuf_drops;
	unsigned long long write_bytes_dropped;
	unsigned long long write_chunks_dropped;
	unsigned long long probe_read_failures;
	unsigned long long dio_iocb_read_failures;
	unsigned long long dio_iovec_read_failures;
	unsigned long long dio_payload_read_failures;
	unsigned long long fallocate_unsupported;
	unsigned long long last_untracked_dev;
	unsigned long long last_untracked_ino;
	unsigned int last_untracked_op;
};

struct statediff_vfs_file_header {
	unsigned int magic;
	unsigned short version;
	unsigned short flags;
	unsigned long long record_count;
	unsigned long long payload_size;
} __attribute__((packed));

struct statediff_vfs_record_header {
	unsigned long long seq;
	unsigned int op;
	unsigned int flags;
	unsigned long long offset;
	unsigned long long size;
	unsigned int mode;
	unsigned int path_len;
	unsigned int new_path_len;
	unsigned int data_len;
} __attribute__((packed));

#endif
