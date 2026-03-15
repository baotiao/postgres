/*-------------------------------------------------------------------------
 *
 * dwbuf.c
 *	  Double Write Buffer implementation.
 *
 * The double write buffer (DWB) provides protection against torn page writes
 * by writing pages to a dedicated buffer file before writing to the actual
 * data files. If a crash occurs during a data file write, the page can be
 * recovered from the DWB.
 *
 * This mechanism provides an additional durable page copy that can be
 * consulted during torn page recovery.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/storage/buffer/dwbuf.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "access/xlog.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "storage/bufmgr.h"
#include "port/pg_crc32c.h"
#include "storage/dwbuf.h"
#include "storage/fd.h"
#include "storage/shmem.h"
#include "utils/guc.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"

/* GUC variables */
int			io_torn_pages_protection = TORN_PAGE_PROTECTION_FULL_PAGES;
bool		double_write_buffer = false;	/* derived from io_torn_pages_protection */
int			double_write_buffer_size = DWBUF_DEFAULT_SIZE_MB;

/*
 * GUC enum options for io_torn_pages_protection.
 */
const struct config_enum_entry io_torn_pages_protection_options[] = {
	{"off", TORN_PAGE_PROTECTION_OFF, false},
	{"full_pages", TORN_PAGE_PROTECTION_FULL_PAGES, false},
	{"double_writes", TORN_PAGE_PROTECTION_DOUBLE_WRITES, false},
	{NULL, 0, false}
};

/*
 * GUC assign hook for io_torn_pages_protection.
 *
 * Derives the internal fullPageWrites and double_write_buffer flags
 * from the unified enum setting.
 */
void
assign_io_torn_pages_protection(int new_value, void *extra)
{
	extern bool fullPageWrites;

	switch (new_value)
	{
		case TORN_PAGE_PROTECTION_OFF:
			fullPageWrites = false;
			double_write_buffer = false;
			break;
		case TORN_PAGE_PROTECTION_FULL_PAGES:
			fullPageWrites = true;
			double_write_buffer = false;
			break;
		case TORN_PAGE_PROTECTION_DOUBLE_WRITES:
			fullPageWrites = false;
			double_write_buffer = true;
			break;
	}
}

/* Shared memory control structure */
static DWBufCtlData *DWBufCtl = NULL;

/* Process ID that opened the files (to detect fork) */
static pid_t DWBufFilesOpenedPid = 0;

/* Per-process file descriptors (FDs are per-process, not shareable) */
static int DWBufFds[DWBUF_MAX_FILES] = {-1, -1, -1, -1, -1, -1, -1, -1,
                                         -1, -1, -1, -1, -1, -1, -1, -1};

/* Directory for DWB files */
#define DWBUF_DIR			"pg_dwbuf"
#define DWBUF_FILE_PREFIX	"dwbuf_"

/* Recovery hash table for page lookup */
static HTAB *dwbuf_recovery_hash = NULL;

/* Recovery hash table entry */
typedef struct DWBufRecoveryEntry
{
	/* Hash key */
	RelFileLocator	rlocator;
	ForkNumber		forknum;
	BlockNumber		blkno;

	/* Data */
	uint32			slot_id;		/* Slot identifier */
	XLogRecPtr		lsn;			/* Page LSN */
	char		   *page_data;		/* In-memory copy of page (BLCKSZ bytes) */
} DWBufRecoveryEntry;

/* Hash key for recovery entries */
typedef struct DWBufRecoveryKey
{
	RelFileLocator	rlocator;
	ForkNumber		forknum;
	BlockNumber		blkno;
} DWBufRecoveryKey;

/* Local buffer for page operations */
static char *dwbuf_page_buffer = NULL;

/*
 * Compute size of shared memory needed for DWB control structure.
 */
Size
DWBufShmemSize(void)
{
	if (!double_write_buffer)
		return 0;

	return MAXALIGN(sizeof(DWBufCtlData));
}

/*
 * Initialize DWB shared memory structures.
 */
void
DWBufShmemInit(void)
{
	bool		found;

	if (!double_write_buffer)
		return;

	DWBufCtl = (DWBufCtlData *)
		ShmemInitStruct("Double Write Buffer",
						DWBufShmemSize(),
						&found);

	if (!found)
	{
		int			total_slots;
		int			slots_per_file;

		/* Calculate number of slots based on configured size */
		total_slots = (double_write_buffer_size * 1024 * 1024) / DWBUF_SLOT_SIZE;
		if (total_slots < DWBUF_MIN_SLOTS)
			total_slots = DWBUF_MIN_SLOTS;

		/* Distribute slots across files */
		DWBufCtl->num_files = (total_slots + DWBUF_SLOTS_PER_FILE - 1) / DWBUF_SLOTS_PER_FILE;
		if (DWBufCtl->num_files > DWBUF_MAX_FILES)
			DWBufCtl->num_files = DWBUF_MAX_FILES;

		slots_per_file = total_slots / DWBufCtl->num_files;
		DWBufCtl->slots_per_file = slots_per_file;
		DWBufCtl->num_slots = slots_per_file * DWBufCtl->num_files;

		/* Initialize atomic variables */
		pg_atomic_init_u64(&DWBufCtl->write_pos, 0);
		pg_atomic_init_u64(&DWBufCtl->flush_pos, 0);
		pg_atomic_init_u32(&DWBufCtl->active_writers, 0);
		pg_atomic_init_u32(&DWBufCtl->resetting, 0);
		pg_atomic_init_u64(&DWBufCtl->checkpoint_start_pos, 0);

		/* Initialize per-file batch fsync tracking */
		for (int f = 0; f < DWBUF_MAX_FILES; f++)
		{
			pg_atomic_init_u64(&DWBufCtl->file_write_gen[f], 0);
			pg_atomic_init_u64(&DWBufCtl->file_sync_gen[f], 0);
			pg_atomic_init_u32(&DWBufCtl->file_syncing[f], 0);
		}

		/* Initialize batch sync coordination */
		pg_atomic_init_u32(&DWBufCtl->batch_pending, 0);
		pg_atomic_init_u64(&DWBufCtl->batch_complete_count, 0);
		ConditionVariableInit(&DWBufCtl->batch_sync_cv);

	}
}

/*
 * Get the path for a DWB segment file.
 */
static void
DWBufFilePath(char *path, int file_idx)
{
	snprintf(path, MAXPGPATH, "%s/%s%03d", DWBUF_DIR, DWBUF_FILE_PREFIX, file_idx);
}

/*
 * Initialize DWB files for this process.
 * This is called lazily the first time DWB is used.
 */
static void
DWBufOpenFiles(void)
{
	int			i;
	char		path[MAXPGPATH];
	struct stat	st;
	pid_t		current_pid = getpid();

	/*
	 * Check if files are already opened in this process.
	 * After fork, the child process will have different PID and needs to
	 * reopen the files.
	 */
	if (DWBufFilesOpenedPid == current_pid && DWBufFds[0] >= 0)
		return;

	/* Close any inherited file descriptors from parent process */
	if (DWBufFilesOpenedPid != current_pid && DWBufFds[0] >= 0)
		DWBufClose();

	if (!DWBufIsEnabled())
		return;

	/* Create directory if it doesn't exist */
	if (stat(DWBUF_DIR, &st) != 0)
	{
		if (MakePGDirectory(DWBUF_DIR) < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not create directory \"%s\": %m", DWBUF_DIR)));
	}

	/* Open or create segment files */
	for (i = 0; i < DWBufCtl->num_files; i++)
	{
		int			fd;
		off_t		expected_size;

		DWBufFilePath(path, i);

		/* Calculate expected file size */
		expected_size = DWBUF_FILE_HEADER_SIZE +
			(off_t) DWBufCtl->slots_per_file * DWBUF_SLOT_SIZE;

		fd = BasicOpenFile(path, O_RDWR | O_CREAT | PG_BINARY);
		if (fd < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not open double write buffer file \"%s\": %m",
							path)));

		/* Extend file if needed */
		if (fstat(fd, &st) == 0 && st.st_size < expected_size)
		{
			if (ftruncate(fd, expected_size) != 0)
			{
				close(fd);
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not extend double write buffer file \"%s\": %m",
								path)));
			}

			/* Initialize the file header (padded to DWBUF_FILE_HEADER_SIZE) */
			{
				PGAlignedBlock hdr_buf;
				DWBufFileHeader *header;

				StaticAssertStmt(sizeof(DWBufFileHeader) <= DWBUF_FILE_HEADER_SIZE,
								 "DWBufFileHeader exceeds DWBUF_FILE_HEADER_SIZE");

				memset(hdr_buf.data, 0, DWBUF_FILE_HEADER_SIZE);
				header = (DWBufFileHeader *) hdr_buf.data;
				header->magic = DWBUF_MAGIC;
				header->version = DWBUF_VERSION;
				header->blcksz = BLCKSZ;
				header->slots_per_file = DWBufCtl->slots_per_file;

				/* Compute CRC */
				INIT_CRC32C(header->crc);
				COMP_CRC32C(header->crc, header, offsetof(DWBufFileHeader, crc));
				FIN_CRC32C(header->crc);

				if (pg_pwrite(fd, hdr_buf.data, DWBUF_FILE_HEADER_SIZE, 0) !=
					DWBUF_FILE_HEADER_SIZE)
				{
					close(fd);
					ereport(ERROR,
							(errcode_for_file_access(),
							 errmsg("could not write double write buffer header: %m")));
				}

				if (pg_fsync(fd) != 0)
				{
					close(fd);
					ereport(ERROR,
							(errcode_for_file_access(),
							 errmsg("could not fsync double write buffer file: %m")));
				}
			}
		}

		DWBufFds[i] = fd;
	}

	/* Allocate local page buffer */
	if (dwbuf_page_buffer == NULL)
		dwbuf_page_buffer = MemoryContextAllocAligned(TopMemoryContext,
													  DWBUF_SLOT_SIZE,
													  PG_IO_ALIGN_SIZE,
													  0);

	DWBufFilesOpenedPid = current_pid;
}

/*
 * Initialize DWB files at startup.
 */
void
DWBufInit(void)
{
	if (!DWBufIsEnabled())
		return;

	DWBufOpenFiles();

	elog(LOG, "double write buffer initialized with %d slots in %d files",
		 DWBufCtl->num_slots, DWBufCtl->num_files);
}

/*
 * Close DWB files at shutdown.
 */
void
DWBufClose(void)
{
	int			i;

	if (DWBufFds[0] < 0)
		return;

	for (i = 0; i < DWBUF_MAX_FILES; i++)
	{
		if (DWBufFds[i] >= 0)
		{
			close(DWBufFds[i]);
			DWBufFds[i] = -1;
		}
	}
	DWBufFilesOpenedPid = 0;
}

/*
 * Write a page to the double write buffer.
 *
 * Returns the file index that was written to, so the caller can fsync
 * that specific file if needed (e.g. for non-checkpoint writes).
 *
 * Returns -1 if DWB is not enabled or if the ring buffer is full (slot
 * reuse would overwrite data not yet protected by a completed checkpoint).
 * In the latter case the caller should fall back to a full page image in WAL.
 *
 * Note: Bulk write paths (COPY, CREATE TABLE AS, index builds) bypass
 * FlushBuffer entirely — they use PageSetChecksumInplace + smgrextend/
 * smgrwriteback.  Those paths are already protected because the relation
 * extension is fully WAL-logged and WAL replay reconstructs the pages.
 */
int
DWBufWritePage(RelFileLocator rlocator, ForkNumber forknum,
			   BlockNumber blkno, const char *page, XLogRecPtr lsn,
			   uint64 *write_gen_out)
{
	uint64		pos;
	uint64		slot_pos;
	int			file_idx;
	int			slot_idx;
	off_t		offset;
	DWBufPageSlot *slot;
	pg_crc32c	crc;

	if (!DWBufIsEnabled())
		return -1;

	/* Ensure files are opened in this process */
	DWBufOpenFiles();

	/*
	 * Coordinate with DWBufPreCheckpoint() and DWBufPostCheckpoint() which
	 * set resetting=1 to quiesce writers.  Writers that race with a quiesce
	 * must either fully complete before the quiesce proceeds, or wait until
	 * it is finished.
	 *
	 * CHECK_FOR_INTERRUPTS() is safe here: active_writers has not yet been
	 * incremented, so an error exit requires no cleanup of shared state.
	 * This also prevents infinite blocking if the checkpointer crashes with
	 * resetting=1 set; a SIGTERM will still let the backend exit cleanly.
	 */
	for (;;)
	{
		while (pg_atomic_read_u32(&DWBufCtl->resetting) != 0)
		{
			CHECK_FOR_INTERRUPTS();
			pg_usleep(100);
		}

		pg_atomic_fetch_add_u32(&DWBufCtl->active_writers, 1);

		if (pg_atomic_read_u32(&DWBufCtl->resetting) == 0)
			break;

		pg_atomic_fetch_sub_u32(&DWBufCtl->active_writers, 1);
	}

	/*
	 * Allocate a slot and check ring-buffer space.  If the ring buffer is
	 * full (write_pos has advanced num_slots past checkpoint_start_pos),
	 * the slot's previous occupant may not have been fsynced yet.  In that
	 * case we release our active_writers count, sleep, and retry from the
	 * top (re-checking the resetting flag).  This blocks until a checkpoint
	 * completes and advances checkpoint_start_pos, similar to InnoDB's
	 * doublewrite behavior.
	 */
	for (;;)
	{
		uint64		ckpt_start;

		pos = pg_atomic_fetch_add_u64(&DWBufCtl->write_pos, 1);

		ckpt_start = pg_atomic_read_u64(&DWBufCtl->checkpoint_start_pos);

		if (pos - ckpt_start < (uint64) DWBufCtl->num_slots)
			break;				/* slot is safe to use */

		/* Ring buffer full — give back writer count and wait */
		pg_atomic_fetch_sub_u32(&DWBufCtl->active_writers, 1);

		ereport(DEBUG2,
				(errmsg("double write buffer ring full, waiting for checkpoint")));

		CHECK_FOR_INTERRUPTS();
		pg_usleep(1000);		/* 1 ms */

		/*
		 * Re-enter the writer registration loop at the top of the
		 * function, which handles the resetting flag properly.
		 */
		for (;;)
		{
			while (pg_atomic_read_u32(&DWBufCtl->resetting) != 0)
			{
				CHECK_FOR_INTERRUPTS();
				pg_usleep(100);
			}

			pg_atomic_fetch_add_u32(&DWBufCtl->active_writers, 1);

			if (pg_atomic_read_u32(&DWBufCtl->resetting) == 0)
				break;

			pg_atomic_fetch_sub_u32(&DWBufCtl->active_writers, 1);
		}
	}

	/* Map linear position to ring buffer slot */
	slot_pos = pos % DWBufCtl->num_slots;

	/* Calculate file and slot indices */
	file_idx = slot_pos / DWBufCtl->slots_per_file;
	slot_idx = slot_pos % DWBufCtl->slots_per_file;

	/* Calculate offset in file */
	offset = DWBUF_FILE_HEADER_SIZE + (off_t) slot_idx * DWBUF_SLOT_SIZE;

	/* Build slot header in local buffer */
	slot = (DWBufPageSlot *) dwbuf_page_buffer;
	slot->crc = 0;				/* zero before CRC computation */
	slot->rlocator = rlocator;
	slot->forknum = forknum;
	slot->blkno = blkno;
	slot->lsn = lsn;
	/*
	 * Truncation to uint32 is safe: DWBufPostCheckpoint resets write_pos
	 * to 0 each cycle, and the ring-buffer overflow check limits pos to
	 * at most 2 * num_slots (~131 K at max config) per cycle.
	 */
	slot->slot_id = (uint32) pos;
	slot->flags = DWBUF_SLOT_VALID;
	slot->checksum = 0;			/* Will be set by PageSetChecksumCopy */

	/* Copy page data after header */
	memcpy(dwbuf_page_buffer + sizeof(DWBufPageSlot), page, BLCKSZ);

	/* Compute CRC over slot header (excluding crc field) and page data */
	INIT_CRC32C(crc);
	COMP_CRC32C(crc, dwbuf_page_buffer + sizeof(pg_crc32c),
				sizeof(DWBufPageSlot) - sizeof(pg_crc32c) + BLCKSZ);
	FIN_CRC32C(crc);
	slot->crc = crc;

	/* Write to DWB file, tracking IO stats */
	{
		instr_time	io_start = pgstat_prepare_io_time(track_io_timing);

		if (pg_pwrite(DWBufFds[file_idx], dwbuf_page_buffer,
					  DWBUF_SLOT_SIZE, offset) != DWBUF_SLOT_SIZE)
		{
			int			save_errno = errno;

			pg_atomic_fetch_sub_u32(&DWBufCtl->active_writers, 1);
			errno = save_errno;
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not write to double write buffer: %m")));
		}

		pgstat_count_io_op_time(IOOBJECT_DWBUF, IOCONTEXT_NORMAL, IOOP_WRITE,
								io_start, 1, DWBUF_SLOT_SIZE);
	}

	/*
	 * Record per-file write generation so the next DWBufFlushFile call knows
	 * which generation it must wait for.  Multiple writers incrementing the
	 * same file_write_gen allows a single fsync to cover all of them.
	 */
	{
		uint64		my_gen =
			pg_atomic_fetch_add_u64(&DWBufCtl->file_write_gen[file_idx], 1) + 1;

		if (write_gen_out != NULL)
			*write_gen_out = my_gen;
	}

	pg_atomic_fetch_sub_u32(&DWBufCtl->active_writers, 1);

	return file_idx;
}

/*
 * Flush all written pages in the DWB to disk.
 */
void
DWBufFlush(void)
{
	int			i;
	uint64		current_pos;
	uint64		flush_pos;

	if (!DWBufIsEnabled())
		return;

	current_pos = pg_atomic_read_u64(&DWBufCtl->write_pos);
	flush_pos = pg_atomic_read_u64(&DWBufCtl->flush_pos);

	/* Nothing to flush */
	if (current_pos <= flush_pos)
		return;

	/* Ensure files are opened in this process */
	if (DWBufFilesOpenedPid != getpid() || DWBufFds[0] < 0)
		DWBufOpenFiles();

	/* Fsync all DWB files and update per-file sync generations */
	for (i = 0; i < DWBufCtl->num_files; i++)
	{
		if (DWBufFds[i] >= 0)
		{
			uint64		cur_write_gen;
			instr_time	io_start = pgstat_prepare_io_time(track_io_timing);

			if (pg_fsync(DWBufFds[i]) != 0)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not fsync double write buffer: %m")));

			pgstat_count_io_op_time(IOOBJECT_DWBUF, IOCONTEXT_NORMAL, IOOP_FSYNC,
									io_start, 1, 0);

			cur_write_gen =
				pg_atomic_read_u64(&DWBufCtl->file_write_gen[i]);
			pg_atomic_write_u64(&DWBufCtl->file_sync_gen[i], cur_write_gen);
		}
	}

	/* Update flush position */
	pg_atomic_write_u64(&DWBufCtl->flush_pos, current_pos);
}

/*
 * Ensure a DWB file is fsynced up to (at least) this process's last write.
 *
 * Uses per-file generation counters so that a single fsync can satisfy many
 * concurrent writers.  The fast path (file already synced past our generation)
 * is just an atomic read — no syscall at all.
 */
void
DWBufFlushFile(int file_idx, uint64 write_gen)
{
	uint64		my_gen = write_gen;

	if (!DWBufIsEnabled())
		return;
	if (file_idx < 0 || file_idx >= DWBufCtl->num_files)
		return;

	/* Fast path: already synced past our write */
	if (pg_atomic_read_u64(&DWBufCtl->file_sync_gen[file_idx]) >= my_gen)
		return;

	/* Ensure files are opened in this process */
	if (DWBufFilesOpenedPid != getpid() || DWBufFds[0] < 0)
		DWBufOpenFiles();

	/*
	 * Try to become the syncer for this file.  If another process is already
	 * fsyncing, wait for it and recheck — its fsync likely covers our write.
	 */
	for (;;)
	{
		uint32		expected = 0;

		if (pg_atomic_compare_exchange_u32(&DWBufCtl->file_syncing[file_idx],
										   &expected, 1))
		{
			instr_time	io_start;
			uint64		cur_write_gen;

			/* Re-check after acquiring: maybe a concurrent syncer just finished */
			if (pg_atomic_read_u64(&DWBufCtl->file_sync_gen[file_idx]) >= my_gen)
			{
				pg_atomic_write_u32(&DWBufCtl->file_syncing[file_idx], 0);
				return;
			}

			/* We are the syncer — fsync covers all writes up to now */
			io_start = pgstat_prepare_io_time(track_io_timing);

			if (DWBufFds[file_idx] >= 0 && pg_fsync(DWBufFds[file_idx]) != 0)
			{
				pg_atomic_write_u32(&DWBufCtl->file_syncing[file_idx], 0);
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not fsync double write buffer file %d: %m",
								file_idx)));
			}

			pgstat_count_io_op_time(IOOBJECT_DWBUF, IOCONTEXT_NORMAL, IOOP_FSYNC,
									io_start, 1, 0);

			/* Advance sync generation to current write generation */
			cur_write_gen =
				pg_atomic_read_u64(&DWBufCtl->file_write_gen[file_idx]);
			pg_atomic_write_u64(&DWBufCtl->file_sync_gen[file_idx],
								cur_write_gen);

			pg_atomic_write_u32(&DWBufCtl->file_syncing[file_idx], 0);
			return;
		}

		/*
		 * Another process is fsyncing — wait for it to finish.
		 * CHECK_FOR_INTERRUPTS() allows SIGTERM to interrupt an arbitrarily
		 * long wait; no shared state was modified so no cleanup is needed.
		 */
		while (pg_atomic_read_u32(&DWBufCtl->file_syncing[file_idx]) != 0)
		{
			CHECK_FOR_INTERRUPTS();
			pg_usleep(10);
		}

		/* Recheck: the completed fsync may cover our write */
		if (pg_atomic_read_u64(&DWBufCtl->file_sync_gen[file_idx]) >= my_gen)
			return;

		/* Rare: syncer finished but didn't cover us. Retry. */
	}
}

/*
 * Leader helper: perform the actual batch fsync for non-checkpoint writers.
 *
 * Fsyncs all dirty DWB files (the per-file generation mechanism
 * automatically skips clean files), advances the batch completion
 * counter, resets the pending counter, and wakes all waiters.
 *
 * The ordering is important: batch_complete_count is advanced *before*
 * batch_pending is reset.  This ensures that a new writer arriving
 * between the advance and the reset reads the updated batch_complete_count
 * and waits for a *subsequent* batch rather than falsely believing it was
 * covered by this one.  See DWBufBatchSync header comment for details.
 */
static void
dwbuf_batch_do_sync(void)
{
	/* Fsync all DWB files that have new writes since last sync */
	for (int f = 0; f < DWBufCtl->num_files; f++)
	{
		uint64		wgen = pg_atomic_read_u64(&DWBufCtl->file_write_gen[f]);

		if (wgen > pg_atomic_read_u64(&DWBufCtl->file_sync_gen[f]))
			DWBufFlushFile(f, wgen);
	}

	/*
	 * Advance completion counter first, then reset pending count.
	 * See function header comment for ordering rationale.
	 */
	pg_atomic_fetch_add_u64(&DWBufCtl->batch_complete_count, 1);
	pg_atomic_write_u32(&DWBufCtl->batch_pending, 0);
	ConditionVariableBroadcast(&DWBufCtl->batch_sync_cv);
}

/*
 * Batch-sync the DWB for non-checkpoint writers.
 *
 * Instead of calling DWBufFlushFile per page, writers register themselves
 * in a batch.  When the batch reaches DWBUF_BATCH_SYNC_THRESHOLD pages
 * the writer that crosses the threshold becomes the leader and fsyncs all
 * dirty DWB files.  Other writers wait on a ConditionVariable; if no
 * leader appears within DWBUF_BATCH_SYNC_TIMEOUT_MS the waiter promotes
 * itself and triggers the fsync.
 *
 * Correctness guarantee: after returning, the caller's DWB page is
 * durable.  The leader's fsync covers all file_write_gen values visible
 * at scan time, but a narrow race exists: a writer whose DWBufWritePage
 * incremented file_write_gen *after* the leader scanned that file may
 * join the batch and wake up believing it was covered.  To close this
 * window, every writer verifies its own file_sync_gen >= write_gen
 * after waking and falls back to DWBufFlushFile if the batch missed it.
 * The fallback fast-path is a single atomic read (no syscall) when the
 * batch did cover the write, so the overhead is negligible.
 */
void
DWBufBatchSync(int file_idx, uint64 write_gen)
{
	uint32		count;
	uint64		my_batch_id;

	/* DWBufWritePage returns -1 when DWB is disabled or ring buffer full */
	if (file_idx < 0)
		return;

	count = pg_atomic_fetch_add_u32(&DWBufCtl->batch_pending, 1) + 1;
	my_batch_id = pg_atomic_read_u64(&DWBufCtl->batch_complete_count);

	if (count >= DWBUF_BATCH_SYNC_THRESHOLD)
	{
		/* Threshold reached — become the leader and fsync */
		dwbuf_batch_do_sync();

		/*
		 * The leader's own write is guaranteed covered (program order:
		 * file_write_gen was incremented before we entered this function,
		 * and we read it in dwbuf_batch_do_sync on the same thread).
		 * No fallback verification needed.
		 */
		return;
	}

	/* Wait for a leader to complete our batch, or timeout */
	ConditionVariablePrepareToSleep(&DWBufCtl->batch_sync_cv);
	for (;;)
	{
		if (pg_atomic_read_u64(&DWBufCtl->batch_complete_count) > my_batch_id)
			break;				/* our batch has been synced */

		if (ConditionVariableTimedSleep(&DWBufCtl->batch_sync_cv,
										DWBUF_BATCH_SYNC_TIMEOUT_MS,
										WAIT_EVENT_DWBUF_BATCH_SYNC))
		{
			/* Timeout — promote ourselves to leader */
			ConditionVariableCancelSleep();
			dwbuf_batch_do_sync();

			/* Same as leader path: our own write is covered. */
			return;
		}
	}
	ConditionVariableCancelSleep();

	/*
	 * We were woken by a leader's broadcast.  The batch fsync *probably*
	 * covered our write, but a race exists: if our DWBufWritePage
	 * incremented file_write_gen after the leader scanned our file, the
	 * fsync may have missed us.  Verify and fall back if needed.
	 *
	 * Fast path (common case): file_sync_gen already >= our write_gen,
	 * so DWBufFlushFile returns immediately with no syscall.
	 */
	DWBufFlushFile(file_idx, write_gen);
}

/*
 * Called before checkpoint to ensure DWB is in consistent state.
 *
 * We must guarantee that DWBufFlush() covers every slot allocated before
 * this point.  A naive approach — read write_pos, then fsync — has a
 * race: a writer might have incremented write_pos but not yet issued its
 * pg_pwrite() when we take the snapshot.  The resulting fsync would skip
 * that slot, leaving it potentially absent from the DWB when the
 * checkpoint relies on it for torn-page protection.
 *
 * The fix is to reuse the resetting flag (also used by DWBufPostCheckpoint)
 * to block new writers, then drain in-flight writers before flushing.
 * Once active_writers reaches zero, every slot with pos < write_pos is
 * guaranteed to have a completed pwrite, so a single DWBufFlush() covers
 * the entire allocated range.
 */
void
DWBufPreCheckpoint(void)
{
	if (!DWBufIsEnabled())
		return;

	/*
	 * Block new writers.  Writers that race with this will spin until
	 * we clear resetting below.  We do not add CHECK_FOR_INTERRUPTS in
	 * the drain loop below because we hold resetting == 1; if we exit via
	 * an error, resetting would remain 1 permanently and block all future
	 * DWB writes.  The drain window is bounded by the pwrite latency of
	 * currently-active writers and is short in practice.
	 */
	pg_atomic_write_u32(&DWBufCtl->resetting, 1);

	/* Drain all in-flight writers so every allocated slot has its pwrite. */
	while (pg_atomic_read_u32(&DWBufCtl->active_writers) != 0)
		pg_usleep(100);

	/*
	 * Now safe to flush: no writer holds a slot between pg_pwrite() and
	 * active_writers decrement.  DWBufFlush() will fsync all data written
	 * up to the current write_pos.
	 */
	DWBufFlush();

	/*
	 * Wake any writers sleeping in DWBufBatchSync.  With resetting == 1
	 * no new writers can enter DWBufWritePage, so the batch threshold may
	 * never be reached and waiters would stall for the full 10 ms timeout.
	 * DWBufFlush() above already fsynced everything, so the woken writers
	 * will find file_sync_gen >= their write_gen and return immediately
	 * from the DWBufFlushFile fallback.
	 */
	pg_atomic_fetch_add_u64(&DWBufCtl->batch_complete_count, 1);
	ConditionVariableBroadcast(&DWBufCtl->batch_sync_cv);

	/*
	 * Record checkpoint_start_pos.  Slots at positions >= this value
	 * belong to the next checkpoint cycle; DWBufWritePage uses this to
	 * detect ring-buffer wrap-around and fall back to FPI when needed.
	 */
	pg_atomic_write_u64(&DWBufCtl->checkpoint_start_pos,
						pg_atomic_read_u64(&DWBufCtl->write_pos));

	/* Allow writers to proceed again. */
	pg_atomic_write_u32(&DWBufCtl->resetting, 0);
}

/*
 * Called after checkpoint to reset DWB for next cycle.
 *
 * Blocks new writers (via resetting=1, the same flag used by
 * DWBufPreCheckpoint), waits for in-flight writers to drain, resets the
 * ring buffer positions, then unblocks.  No file I/O is needed — the
 * on-disk slot data is only consulted during crash recovery, and the
 * CRC-based validation in DWBufRecoveryInit() handles stale slots.
 *
 * We do not add CHECK_FOR_INTERRUPTS in the drain loop below because we
 * hold resetting == 1; an error exit would leave resetting permanently set,
 * blocking all future DWB writes.  The drain is bounded by the pwrite
 * latency of active writers and completes quickly in practice.
 */
void
DWBufPostCheckpoint(void)
{
	if (!DWBufIsEnabled())
		return;

	/* Block new writers and wait until current writers drain. */
	pg_atomic_write_u32(&DWBufCtl->resetting, 1);
	while (pg_atomic_read_u32(&DWBufCtl->active_writers) != 0)
		pg_usleep(100);

	/* Now safe to reset positions for new cycle */
	pg_atomic_write_u64(&DWBufCtl->write_pos, 0);
	pg_atomic_write_u64(&DWBufCtl->flush_pos, 0);

	/*
	 * Reset checkpoint_start_pos to 0 to match write_pos.  Without this,
	 * DWBufWritePage would compute (pos - old_checkpoint_start_pos) with
	 * uint64 underflow for every write until the next DWBufPreCheckpoint,
	 * triggering the overflow guard and returning -1 for all DWB writes.
	 */
	pg_atomic_write_u64(&DWBufCtl->checkpoint_start_pos, 0);

	/*
	 * Reset batch_pending so stale increments from writers that ran
	 * during the checkpoint don't carry over and trigger a premature
	 * batch sync on the first few writes of the new cycle.
	 */
	pg_atomic_write_u32(&DWBufCtl->batch_pending, 0);

	pg_atomic_write_u32(&DWBufCtl->resetting, 0);
}

/*
 * Initialize DWB for recovery.
 * Scans DWB files and builds a hash table of valid pages.
 */
void
DWBufRecoveryInit(void)
{
	HASHCTL		hash_ctl;
	int			i;
	char		path[MAXPGPATH];
	char	   *buffer;

	if (!double_write_buffer)
		return;

	/* Rebuild from disk to ensure we use the latest durable DWB contents. */
	if (dwbuf_recovery_hash != NULL)
	{
		hash_destroy(dwbuf_recovery_hash);
		dwbuf_recovery_hash = NULL;
	}

	/* Create hash table for page lookup */
	memset(&hash_ctl, 0, sizeof(hash_ctl));
	hash_ctl.keysize = sizeof(DWBufRecoveryKey);
	hash_ctl.entrysize = sizeof(DWBufRecoveryEntry);
	hash_ctl.hcxt = TopMemoryContext;

	dwbuf_recovery_hash = hash_create("DWBuf Recovery Hash",
									  1024,
									  &hash_ctl,
									  HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);

	/* Allocate buffer for reading slots */
	buffer = palloc_aligned(DWBUF_SLOT_SIZE, PG_IO_ALIGN_SIZE, 0);

	/* Scan all DWB files */
	for (i = 0; i < DWBUF_MAX_FILES; i++)
	{
		int			fd;
		DWBufFileHeader header;
		int			slot_idx;
		struct stat st;

		DWBufFilePath(path, i);

		/* Check if file exists */
		if (stat(path, &st) != 0)
			continue;

		fd = BasicOpenFile(path, O_RDONLY | PG_BINARY);
		if (fd < 0)
		{
			elog(WARNING, "could not open DWB file \"%s\" for recovery: %m", path);
			continue;
		}

		/* Read and validate header */
		if (pg_pread(fd, &header, sizeof(header), 0) != sizeof(header))
		{
			close(fd);
			continue;
		}

		if (header.magic != DWBUF_MAGIC || header.version != DWBUF_VERSION)
		{
			close(fd);
			continue;
		}

		/* Verify header CRC */
		{
			pg_crc32c	crc;

			INIT_CRC32C(crc);
			COMP_CRC32C(crc, &header, offsetof(DWBufFileHeader, crc));
			FIN_CRC32C(crc);

			if (!EQ_CRC32C(crc, header.crc))
			{
				elog(WARNING, "DWB file \"%s\" has invalid header CRC", path);
				close(fd);
				continue;
			}
		}

		/* Scan slots in this file */
		for (slot_idx = 0; slot_idx < (int) header.slots_per_file; slot_idx++)
		{
			off_t		offset;
			DWBufPageSlot *slot;
			pg_crc32c	crc;
			DWBufRecoveryKey key;
			DWBufRecoveryEntry *entry;
			bool		found;

			offset = DWBUF_FILE_HEADER_SIZE + (off_t) slot_idx * DWBUF_SLOT_SIZE;

			if (pg_pread(fd, buffer, DWBUF_SLOT_SIZE, offset) != DWBUF_SLOT_SIZE)
				break;

			slot = (DWBufPageSlot *) buffer;

			/* Check if slot is valid */
			if (!(slot->flags & DWBUF_SLOT_VALID))
				continue;

			/* Verify slot CRC */
			INIT_CRC32C(crc);
			COMP_CRC32C(crc, buffer + sizeof(pg_crc32c),
						sizeof(DWBufPageSlot) - sizeof(pg_crc32c) + BLCKSZ);
			FIN_CRC32C(crc);

			if (!EQ_CRC32C(crc, slot->crc))
				continue;		/* Invalid CRC, skip */

			/* Add to hash table (newer entries override older ones) */
			key.rlocator = slot->rlocator;
			key.forknum = slot->forknum;
			key.blkno = slot->blkno;

			entry = hash_search(dwbuf_recovery_hash, &key, HASH_ENTER, &found);

			if (!found ||
				entry->lsn < slot->lsn ||
				(entry->lsn == slot->lsn && entry->slot_id < slot->slot_id))
			{
				entry->rlocator = slot->rlocator;
				entry->forknum = slot->forknum;
				entry->blkno = slot->blkno;
				entry->slot_id = slot->slot_id;
				entry->lsn = slot->lsn;

				/*
				 * Store page data in memory so recovery does not need to
				 * re-read from DWB files (which may be overwritten by new
				 * DWB writes during WAL replay).
				 */
				if (entry->page_data == NULL)
					entry->page_data = MemoryContextAlloc(TopMemoryContext,
														  BLCKSZ);
				memcpy(entry->page_data,
					   buffer + sizeof(DWBufPageSlot), BLCKSZ);
			}
		}

		close(fd);
	}

	pfree(buffer);

	elog(DEBUG1, "double write buffer recovery initialized with %ld pages",
		 (long) hash_get_num_entries(dwbuf_recovery_hash));
}

/*
 * Try to recover a page from DWB.
 *
 * Uses the in-memory page copies built by DWBufRecoveryInit() during
 * startup, so this never re-reads from DWB files (which may have been
 * overwritten by new DWB writes during WAL replay).
 *
 * Returns true if page was recovered, false otherwise.
 */
bool
DWBufRecoverPage(RelFileLocator rlocator, ForkNumber forknum,
				 BlockNumber blkno, char *page)
{
	DWBufRecoveryKey key;
	DWBufRecoveryEntry *entry;

	if (dwbuf_recovery_hash == NULL)
		return false;

	/* Look up page in hash table */
	key.rlocator = rlocator;
	key.forknum = forknum;
	key.blkno = blkno;

	entry = hash_search(dwbuf_recovery_hash, &key, HASH_FIND, NULL);
	if (entry == NULL || entry->page_data == NULL)
		return false;

	/* Copy page data from in-memory store */
	memcpy(page, entry->page_data, BLCKSZ);

	elog(DEBUG1, "recovered page %u/%u/%u fork %d block %u from DWB",
		 rlocator.spcOid, rlocator.dbOid, rlocator.relNumber,
		 forknum, blkno);

	return true;
}

/*
 * Finish DWB recovery and clean up.
 */
void
DWBufRecoveryFinish(void)
{
	if (dwbuf_recovery_hash != NULL)
	{
		hash_destroy(dwbuf_recovery_hash);
		dwbuf_recovery_hash = NULL;
	}
}

/*
 * Check if DWB is enabled.
 */
bool
DWBufIsEnabled(void)
{
	return double_write_buffer && DWBufCtl != NULL;
}


/*
 * Process-local flag: when true, FlushBuffer skips per-page DWB writes
 * because checkpoint Phase 1 has already written all pages to DWB and
 * fsynced them in batch.
 */
static bool dwbuf_checkpoint_writes_done = false;

void
DWBufSetCheckpointWritesDone(bool done)
{
	dwbuf_checkpoint_writes_done = done;
}

bool
DWBufCheckpointWritesDone(void)
{
	return dwbuf_checkpoint_writes_done;
}
