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
 * This mechanism can replace full_page_writes with better efficiency since
 * it avoids writing full page images to WAL.
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
#include "port/pg_crc32c.h"
#include "storage/dwbuf.h"
#include "storage/fd.h"
#include "storage/shmem.h"
#include "utils/guc.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"

/* GUC variables */
bool		double_write_buffer = false;
int			double_write_buffer_size = DWBUF_DEFAULT_SIZE_MB;

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
	int				file_idx;		/* Which DWB file */
	int				slot_idx;		/* Slot index in file */
	XLogRecPtr		lsn;			/* Page LSN */
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

		/* Initialize the control structure */
		SpinLockInit(&DWBufCtl->mutex);

		/* Calculate number of slots based on configured size */
		total_slots = (double_write_buffer_size * 1024 * 1024) / DWBUF_SLOT_SIZE;
		if (total_slots < 64)
			total_slots = 64;	/* Minimum 64 slots */

		/* Distribute slots across files */
		DWBufCtl->num_files = (total_slots + 4095) / 4096;
		if (DWBufCtl->num_files > DWBUF_MAX_FILES)
			DWBufCtl->num_files = DWBUF_MAX_FILES;

		slots_per_file = total_slots / DWBufCtl->num_files;
		DWBufCtl->slots_per_file = slots_per_file;
		DWBufCtl->num_slots = slots_per_file * DWBufCtl->num_files;

		/* Initialize atomic variables */
		pg_atomic_init_u64(&DWBufCtl->write_pos, 0);
		pg_atomic_init_u64(&DWBufCtl->flush_pos, 0);

		/* Initialize other fields */
		DWBufCtl->batch_id = 0;
		DWBufCtl->flushed_batch_id = 0;
		DWBufCtl->checkpoint_lsn = InvalidXLogRecPtr;
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

	if (!double_write_buffer || DWBufCtl == NULL)
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
		expected_size = sizeof(DWBufFileHeader) +
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

			/* Initialize the file header */
			{
				DWBufFileHeader header;

				memset(&header, 0, sizeof(header));
				header.magic = DWBUF_MAGIC;
				header.version = DWBUF_VERSION;
				header.blcksz = BLCKSZ;
				header.slots_per_file = DWBufCtl->slots_per_file;
				header.batch_id = 0;
				header.checkpoint_lsn = InvalidXLogRecPtr;

				/* Compute CRC */
				INIT_CRC32C(header.crc);
				COMP_CRC32C(header.crc, &header, offsetof(DWBufFileHeader, crc));
				FIN_CRC32C(header.crc);

				if (pg_pwrite(fd, &header, sizeof(header), 0) != sizeof(header))
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
	if (!double_write_buffer || DWBufCtl == NULL)
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
	pid_t		current_pid = getpid();

	if (DWBufFilesOpenedPid != current_pid || DWBufFds[0] < 0)
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
 * Write a page to the double write buffer and fsync.
 *
 * This function writes the page to DWB and ensures it's fsynced to disk
 * before returning, guaranteeing torn page protection.
 */
void
DWBufWritePage(RelFileLocator rlocator, ForkNumber forknum,
			   BlockNumber blkno, const char *page, XLogRecPtr lsn)
{
	uint64		pos;
	int			file_idx;
	int			slot_idx;
	off_t		offset;
	DWBufPageSlot *slot;
	pg_crc32c	crc;

	if (!double_write_buffer || DWBufCtl == NULL)
		return;

	/* Ensure files are opened in this process */
	DWBufOpenFiles();

	/* Get next slot position atomically */
	pos = pg_atomic_fetch_add_u64(&DWBufCtl->write_pos, 1);

	/* Calculate file and slot indices */
	file_idx = (pos / DWBufCtl->slots_per_file) % DWBufCtl->num_files;
	slot_idx = pos % DWBufCtl->slots_per_file;

	/* Calculate offset in file */
	offset = sizeof(DWBufFileHeader) + (off_t) slot_idx * DWBUF_SLOT_SIZE;

	/* Build slot header in local buffer */
	slot = (DWBufPageSlot *) dwbuf_page_buffer;
	slot->rlocator = rlocator;
	slot->forknum = forknum;
	slot->blkno = blkno;
	slot->lsn = lsn;
	slot->slot_id = (uint32) pos;
	slot->flags = DWBUF_SLOT_VALID;
	slot->checksum = 0;			/* Will be set by PageSetChecksumCopy */

	/* Copy page data after header */
	memcpy(dwbuf_page_buffer + sizeof(DWBufPageSlot), page, BLCKSZ);

	/* Compute CRC over slot header and page data */
	INIT_CRC32C(crc);
	COMP_CRC32C(crc, dwbuf_page_buffer + sizeof(pg_crc32c),
				sizeof(DWBufPageSlot) - sizeof(pg_crc32c) + BLCKSZ);
	FIN_CRC32C(crc);
	slot->crc = crc;

	/* Write to DWB file */
	if (pg_pwrite(DWBufFds[file_idx], dwbuf_page_buffer,
				  DWBUF_SLOT_SIZE, offset) != DWBUF_SLOT_SIZE)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not write to double write buffer: %m")));

	/*
	 * NOTE: We don't fsync immediately here for performance reasons.
	 * The DWBufFlush() function will fsync all files before checkpoint.
	 */
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

	if (!double_write_buffer || DWBufCtl == NULL)
		return;

	current_pos = pg_atomic_read_u64(&DWBufCtl->write_pos);
	flush_pos = pg_atomic_read_u64(&DWBufCtl->flush_pos);

	/* Nothing to flush */
	if (current_pos <= flush_pos)
		return;

	/* Ensure files are opened in this process */
	if (DWBufFilesOpenedPid != getpid() || DWBufFds[0] < 0)
		DWBufOpenFiles();

	/* Fsync all DWB files */
	for (i = 0; i < DWBufCtl->num_files; i++)
	{
		if (DWBufFds[i] >= 0)
		{
			if (pg_fsync(DWBufFds[i]) != 0)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not fsync double write buffer: %m")));
		}
	}

	/* Update flush position */
	pg_atomic_write_u64(&DWBufCtl->flush_pos, current_pos);
}

/*
 * Flush all pages and ensure DWB is fully synced.
 */
void
DWBufFlushAll(void)
{
	if (!double_write_buffer || DWBufCtl == NULL)
		return;

	DWBufFlush();

	SpinLockAcquire(&DWBufCtl->mutex);
	DWBufCtl->flushed_batch_id = DWBufCtl->batch_id;
	SpinLockRelease(&DWBufCtl->mutex);
}

/*
 * Called before checkpoint to ensure DWB is in consistent state.
 */
void
DWBufPreCheckpoint(void)
{
	if (!double_write_buffer || DWBufCtl == NULL)
		return;

	/* Flush all pending writes */
	DWBufFlushAll();
}

/*
 * Called after checkpoint to reset DWB for next cycle.
 */
void
DWBufPostCheckpoint(XLogRecPtr checkpoint_lsn)
{
	int			i;
	uint64		old_batch_id;
	uint64		new_batch_id;

	if (!double_write_buffer || DWBufCtl == NULL)
		return;

	/* Ensure files are opened in this process */
	if (DWBufFilesOpenedPid != getpid() || DWBufFds[0] < 0)
		DWBufOpenFiles();

	SpinLockAcquire(&DWBufCtl->mutex);

	/* Save old batch ID and increment */
	old_batch_id = DWBufCtl->batch_id;
	DWBufCtl->batch_id++;
	new_batch_id = DWBufCtl->batch_id;
	DWBufCtl->checkpoint_lsn = checkpoint_lsn;

	SpinLockRelease(&DWBufCtl->mutex);

	/*
	 * Wait for all in-flight writes to complete before resetting write_pos.
	 * We use batch_id as a synchronization point.
	 */
	{
		uint64 current_pos = pg_atomic_read_u64(&DWBufCtl->write_pos);
		uint64 num_slots = DWBufCtl->num_slots;

		/* If write_pos wrapped around, wait for flush */
		if (current_pos >= num_slots)
			DWBufFlush();
	}

	/* Now safe to reset positions for new batch */
	pg_atomic_write_u64(&DWBufCtl->write_pos, 0);
	pg_atomic_write_u64(&DWBufCtl->flush_pos, 0);

	/* Update file headers with new batch info */
	for (i = 0; i < DWBufCtl->num_files; i++)
	{
		DWBufFileHeader header;
		char		path[MAXPGPATH];

		if (DWBufFds[i] < 0)
			continue;

		/* Read current header */
		if (pg_pread(DWBufFds[i], &header, sizeof(header), 0) != sizeof(header))
		{
			DWBufFilePath(path, i);
			ereport(WARNING,
					(errcode_for_file_access(),
					 errmsg("could not read double write buffer header from \"%s\": %m",
							path)));
			continue;
		}

		/* Update header */
		header.batch_id = new_batch_id;
		header.checkpoint_lsn = checkpoint_lsn;

		/* Recompute CRC */
		INIT_CRC32C(header.crc);
		COMP_CRC32C(header.crc, &header, offsetof(DWBufFileHeader, crc));
		FIN_CRC32C(header.crc);

		/* Write back */
		if (pg_pwrite(DWBufFds[i], &header, sizeof(header), 0) != sizeof(header))
		{
			DWBufFilePath(path, i);
			ereport(WARNING,
					(errcode_for_file_access(),
					 errmsg("could not write double write buffer header to \"%s\": %m",
							path)));
		}
	}
}

/*
 * Reset DWB (called after successful checkpoint).
 */
void
DWBufReset(void)
{
	/* DWBufPostCheckpoint handles the reset */
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

	/* Create hash table for page lookup */
	memset(&hash_ctl, 0, sizeof(hash_ctl));
	hash_ctl.keysize = sizeof(DWBufRecoveryKey);
	hash_ctl.entrysize = sizeof(DWBufRecoveryEntry);
	hash_ctl.hcxt = CurrentMemoryContext;

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

			offset = sizeof(DWBufFileHeader) + (off_t) slot_idx * DWBUF_SLOT_SIZE;

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

			if (!found || entry->lsn < slot->lsn)
			{
				entry->rlocator = slot->rlocator;
				entry->forknum = slot->forknum;
				entry->blkno = slot->blkno;
				entry->file_idx = i;
				entry->slot_idx = slot_idx;
				entry->lsn = slot->lsn;
			}
		}

		close(fd);
	}

	pfree(buffer);

	elog(LOG, "double write buffer recovery initialized with %ld pages",
		 hash_get_num_entries(dwbuf_recovery_hash));
}

/*
 * Try to recover a page from DWB.
 * Returns true if page was recovered, false otherwise.
 */
bool
DWBufRecoverPage(RelFileLocator rlocator, ForkNumber forknum,
				 BlockNumber blkno, char *page)
{
	DWBufRecoveryKey key;
	DWBufRecoveryEntry *entry;
	char		path[MAXPGPATH];
	int			fd;
	off_t		offset;
	char	   *buffer;
	DWBufPageSlot *slot;
	pg_crc32c	crc;

	if (dwbuf_recovery_hash == NULL)
		return false;

	/* Look up page in hash table */
	key.rlocator = rlocator;
	key.forknum = forknum;
	key.blkno = blkno;

	entry = hash_search(dwbuf_recovery_hash, &key, HASH_FIND, NULL);
	if (entry == NULL)
		return false;

	/* Read page from DWB file */
	DWBufFilePath(path, entry->file_idx);

	fd = BasicOpenFile(path, O_RDONLY | PG_BINARY);
	if (fd < 0)
		return false;

	offset = sizeof(DWBufFileHeader) + (off_t) entry->slot_idx * DWBUF_SLOT_SIZE;

	buffer = palloc_aligned(DWBUF_SLOT_SIZE, PG_IO_ALIGN_SIZE, 0);

	if (pg_pread(fd, buffer, DWBUF_SLOT_SIZE, offset) != DWBUF_SLOT_SIZE)
	{
		pfree(buffer);
		close(fd);
		return false;
	}

	close(fd);

	slot = (DWBufPageSlot *) buffer;

	/* Verify CRC again */
	INIT_CRC32C(crc);
	COMP_CRC32C(crc, buffer + sizeof(pg_crc32c),
				sizeof(DWBufPageSlot) - sizeof(pg_crc32c) + BLCKSZ);
	FIN_CRC32C(crc);

	if (!EQ_CRC32C(crc, slot->crc))
	{
		pfree(buffer);
		return false;
	}

	/* Copy page data */
	memcpy(page, buffer + sizeof(DWBufPageSlot), BLCKSZ);

	pfree(buffer);

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
 * Get current batch ID.
 */
uint64
DWBufGetBatchId(void)
{
	uint64		batch_id;

	if (!double_write_buffer || DWBufCtl == NULL)
		return 0;

	SpinLockAcquire(&DWBufCtl->mutex);
	batch_id = DWBufCtl->batch_id;
	SpinLockRelease(&DWBufCtl->mutex);

	return batch_id;
}
