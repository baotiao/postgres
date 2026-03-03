/*-------------------------------------------------------------------------
 *
 * dwbuf.h
 *	  Double Write Buffer definitions.
 *
 * The double write buffer provides protection against torn page writes
 * by writing pages to a dedicated buffer file before writing to the
 * actual data files. This provides an additional durable copy that can
 * be used for torn page recovery.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/dwbuf.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef DWBUF_H
#define DWBUF_H

#include "storage/block.h"
#include "storage/buf.h"
#include "storage/relfilelocator.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "port/atomics.h"
#include "port/pg_crc32c.h"
#include "access/xlogdefs.h"

/*
 * Double write buffer slot header.
 * Each slot in the DWB file contains this header followed by the page data.
 */
typedef struct DWBufPageSlot
{
	pg_crc32c		crc;			/* CRC of slot header + page — MUST BE FIRST */
	RelFileLocator	rlocator;		/* Relation file locator */
	ForkNumber		forknum;		/* Fork number */
	BlockNumber		blkno;			/* Block number in relation */
	XLogRecPtr		lsn;			/* Page LSN at write time */
	uint32			slot_id;		/* Slot identifier */
	uint16			flags;			/* Slot flags */
	uint16			checksum;		/* Page checksum (if enabled) */
} DWBufPageSlot;

/* Slot flags */
#define DWBUF_SLOT_VALID		0x0001	/* Slot contains valid data */

/*
 * Double write buffer file header.
 * This is stored at the beginning of each DWB segment file.
 */
typedef struct DWBufFileHeader
{
	uint32			magic;			/* Magic number for validation */
	uint32			version;		/* Format version */
	uint32			blcksz;			/* Block size (must match BLCKSZ) */
	uint32			slots_per_file;	/* Number of slots in this file */
	pg_crc32c		crc;			/* CRC of this header */
} DWBufFileHeader;

#define DWBUF_MAGIC			0x44574246	/* "DWBF" */
#define DWBUF_VERSION		1

/*
 * Size of each slot in the DWB file (header + page data), aligned to
 * PG_IO_ALIGN_SIZE (typically 4096) for optimal direct I/O performance.
 */
#define DWBUF_SLOT_SIZE		TYPEALIGN(PG_IO_ALIGN_SIZE, sizeof(DWBufPageSlot) + BLCKSZ)

/*
 * File header occupies a full alignment block so that the first slot
 * starts at a PG_IO_ALIGN_SIZE boundary.
 */
#define DWBUF_FILE_HEADER_SIZE	PG_IO_ALIGN_SIZE

/* Maximum number of DWB segment files */
#define DWBUF_MAX_FILES		16

/* Minimum number of slots (floor applied during size calculation) */
#define DWBUF_MIN_SLOTS		64

/* Slots per DWB segment file */
#define DWBUF_SLOTS_PER_FILE	4096

/*
 * Double write buffer shared control structure.
 * This is stored in shared memory and coordinates access to the DWB.
 */
typedef struct DWBufCtlData
{
	/* Current state */
	pg_atomic_uint64	write_pos;		/* Next slot to write */
	pg_atomic_uint64	flush_pos;		/* Last flushed position */
	pg_atomic_uint32	active_writers; /* Number of in-flight writers */
	pg_atomic_uint32	resetting;		/* 1 during PostCheckpoint reset */

	/*
	 * Slot reuse safety.  Records the write_pos at the start of each
	 * checkpoint.  When write_pos wraps the ring buffer and would reuse a
	 * slot written since checkpoint_start_pos, DWBufWritePage returns -1
	 * so the caller falls back to a full page image in WAL.
	 */
	pg_atomic_uint64	checkpoint_start_pos;

	/*
	 * Per-file batch fsync tracking.
	 *
	 * Each DWBufWritePage increments file_write_gen for the target file.
	 * DWBufFlushFile only issues pg_fsync when file_sync_gen < the caller's
	 * write generation; a single fsync covers all preceding writes.
	 * file_syncing is 1 while an fsync is in progress to avoid thundering
	 * herd fsyncs.
	 */
	pg_atomic_uint64	file_write_gen[DWBUF_MAX_FILES];
	pg_atomic_uint64	file_sync_gen[DWBUF_MAX_FILES];
	pg_atomic_uint32	file_syncing[DWBUF_MAX_FILES];

	/* Configuration (set at startup) */
	int				num_slots;		/* Total number of slots */
	int				num_files;		/* Number of segment files */
	int				slots_per_file;	/* Slots per segment file */
} DWBufCtlData;

/* Default and limits for double_write_buffer_size (in MB) */
#define DWBUF_DEFAULT_SIZE_MB	64
#define DWBUF_MIN_SIZE_MB		16
#define DWBUF_MAX_SIZE_MB		1024

/*
 * Torn page protection methods.
 *
 * Controls how PostgreSQL protects against partial (torn) page writes.
 * Replaces the legacy full_page_writes boolean and the double_write_buffer
 * boolean with a single unified setting.
 */
typedef enum TornPageProtection
{
	TORN_PAGE_PROTECTION_OFF = 0,			/* No protection */
	TORN_PAGE_PROTECTION_FULL_PAGES = 1,	/* Full page images in WAL */
	TORN_PAGE_PROTECTION_DOUBLE_WRITES = 2	/* Double write buffer file */
} TornPageProtection;

/*
 * Global variables
 */
extern PGDLLIMPORT int io_torn_pages_protection;
extern PGDLLIMPORT bool double_write_buffer;	/* derived from io_torn_pages_protection */
extern PGDLLIMPORT int double_write_buffer_size;

/*
 * Function prototypes
 */

/* Initialization and shutdown */
extern Size DWBufShmemSize(void);
extern void DWBufShmemInit(void);
extern void DWBufInit(void);
extern void DWBufClose(void);

/* Write operations */
extern int DWBufWritePage(RelFileLocator rlocator, ForkNumber forknum,
						  BlockNumber blkno, const char *page,
						  XLogRecPtr lsn, uint64 *write_gen_out);
extern void DWBufFlushFile(int file_idx, uint64 write_gen);
extern void DWBufFlush(void);

/* Checkpoint batch write support */
extern void DWBufSetCheckpointWritesDone(bool done);
extern bool DWBufCheckpointWritesDone(void);

/* Checkpoint integration */
extern void DWBufPreCheckpoint(void);
extern void DWBufPostCheckpoint(void);

/* Recovery operations */
extern void DWBufRecoveryInit(void);
extern bool DWBufRecoverPage(RelFileLocator rlocator, ForkNumber forknum,
							 BlockNumber blkno, char *page);
extern void DWBufRecoveryFinish(void);

/* Utility functions */
extern bool DWBufIsEnabled(void);

#endif							/* DWBUF_H */
