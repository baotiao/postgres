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
#include "storage/spin.h"
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
#define DWBUF_SLOT_FLUSHED		0x0002	/* Slot has been flushed to disk */

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
	uint64			batch_id;		/* Current batch ID */
	XLogRecPtr		checkpoint_lsn;	/* LSN of last checkpoint */
	pg_crc32c		crc;			/* CRC of this header */
} DWBufFileHeader;

#define DWBUF_MAGIC			0x44574246	/* "DWBF" */
#define DWBUF_VERSION		1

/*
 * Size of each slot in the DWB file (header + page data, aligned)
 */
#define DWBUF_SLOT_SIZE		MAXALIGN(sizeof(DWBufPageSlot) + BLCKSZ)

/*
 * Double write buffer shared control structure.
 * This is stored in shared memory and coordinates access to the DWB.
 */
typedef struct DWBufCtlData
{
	slock_t			mutex;			/* Protects shared state */

	/* Current state */
	pg_atomic_uint64	write_pos;		/* Next slot to write */
	pg_atomic_uint64	flush_pos;		/* Last flushed position */
	pg_atomic_uint32	active_writers; /* Number of in-flight writers */
	pg_atomic_uint32	resetting;		/* 1 during PostCheckpoint reset */
	uint64			batch_id;		/* Current batch ID */
	uint64			flushed_batch_id;	/* Last fully flushed batch */
	XLogRecPtr		checkpoint_lsn;	/* LSN of last checkpoint */

	/* Configuration (set at startup) */
	int				num_slots;		/* Total number of slots */
	int				num_files;		/* Number of segment files */
	int				slots_per_file;	/* Slots per segment file */
} DWBufCtlData;

/* Maximum number of DWB segment files */
#define DWBUF_MAX_FILES		16

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
						  XLogRecPtr lsn);
extern void DWBufFlushFile(int file_idx);
extern void DWBufFlush(void);
extern void DWBufFlushAll(void);

/* Checkpoint integration */
extern void DWBufPreCheckpoint(void);
extern void DWBufPostCheckpoint(XLogRecPtr checkpoint_lsn);
extern void DWBufReset(void);

/* Recovery operations */
extern void DWBufRecoveryInit(void);
extern bool DWBufRecoverPage(RelFileLocator rlocator, ForkNumber forknum,
							 BlockNumber blkno, char *page);
extern void DWBufRecoveryFinish(void);

/* Utility functions */
extern bool DWBufIsEnabled(void);
extern uint64 DWBufGetBatchId(void);

#endif							/* DWBUF_H */
