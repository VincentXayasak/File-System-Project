#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

// Phase 1. Might need to be changed later when other phases get implemented.

// Disk info in the superblock (First block in the disk)
struct __attribute__((packed)) superblock
{
	char signature[8];	   // Signature = "ECS150FS"
	uint16_t total_blocks; // Total blocks in disk
	uint16_t root_index;   // Root directory block index
	uint16_t data_index;   // First data block index
	uint16_t data_count;   // Number of data blocks
	uint8_t fat_blocks;	   // Number of FAT blocks
	uint8_t padding[4079]; // Unused/padding
};

// Root directory info
struct __attribute__((packed)) root_directory
{
	char filename[FS_FILENAME_LEN]; // Null-terminated filename
	uint32_t size;					// File size in bytes
	uint16_t data_index;			// Index of first data block
	uint8_t padding[10];			// Unused
};

// Once fs_mount reads data from disk, store in global memory
static struct superblock sb;							  // Holds superblock contents
static uint16_t *fat = NULL;							  // FAT entries (array of uint16_t)
static struct root_directory root_dir[FS_FILE_MAX_COUNT]; // Root directory
static int fs_mounted = 0;								  // Is the FS currently mounted?

int fs_mount(const char *diskname)
{
	// Check if the filesystem is already mounted
	if (fs_mounted)
		return -1;

	// Validate input: diskname must not be NULL
	if (!diskname)
		return -1;

	// Attempt to open the virtual disk file
	if (block_disk_open(diskname) < 0)
		return -1;

	// Buffer to hold raw block data (used to read the superblock)
	uint8_t buffer[BLOCK_SIZE];

	// Read block 0 (the superblock) into the buffer
	if (block_read(0, buffer) < 0)
	{
		block_disk_close(); // cleanup on failure
		return -1;
	}

	// Copy the superblock bytes into the structured superblock in memory
	memcpy(&sb, buffer, sizeof(struct superblock));

	// Verify the filesystem signature matches "ECS150FS"
	if (memcmp(sb.signature, "ECS150FS", 8) != 0)
	{
		block_disk_close(); // invalid filesystem
		return -1;
	}

	// Check that the superblock's block count matches the actual disk size
	if (sb.total_blocks != (uint16_t)block_disk_count())
	{
		block_disk_close();
		return -1;
	}

	// Allocate memory for the FAT (one entry per data block, each is 2 bytes)
	// fat = malloc(sb.data_count * sizeof(uint16_t));
	fat = malloc(sb.fat_blocks * BLOCK_SIZE);
	if (!fat)
	{
		block_disk_close();
		return -1;
	}

	// Read each FAT block from disk into memory
	for (int i = 0; i < sb.fat_blocks; i++)
	{
		// Offset starts at block 1 (right after the superblock)
		// Copy each block's 4096 bytes into the correct part of the FAT buffer
		if (block_read(1 + i, ((uint8_t *)fat) + i * BLOCK_SIZE) < 0)
		{
			free(fat); // cleanup on error
			fat = NULL;
			block_disk_close();
			return -1;
		}
	}

	// Read the root directory block into the root_dir array
	if (block_read(sb.root_index, root_dir) < 0)
	{
		free(fat);
		fat = NULL;
		block_disk_close();
		return -1;
	}

	// Mark the filesystem as successfully mounted
	fs_mounted = 1;
	return 0;
}

int fs_umount(void)
{
	// Check if FS is not mounted
	if (!fs_mounted)
		return -1;

	// Free dynamically allocated memory
	free(fat);
	fat = NULL;

	// Resets superblock and root_dir (optional but clean)
	memset(&sb, 0, sizeof(sb));
	memset(root_dir, 0, sizeof(root_dir));

	// Closes the virtual disk
	if (block_disk_close() < 0)
		return -1;

	// Marks FS as unmounted
	fs_mounted = 0;
	return 0;
}

int fs_info(void)
{
	if (!fs_mounted)
		return -1;

	printf("FS Info:\n");
	printf("total_blk_count=%u\n", sb.total_blocks);
	printf("fat_blk_count=%u\n", sb.fat_blocks);
	printf("rdir_blk=%u\n", sb.root_index);
	printf("data_blk=%u\n", sb.data_index);
	printf("data_blk_count=%u\n", sb.data_count);

	// FAT Free Count
	size_t fat_free = 0;
	size_t fat_used = 0;

	// Number of FAT entries = number of data blocks
	for (size_t i = 0; i < sb.data_count; i++)
	{
		if (((uint16_t *)fat)[i] == 0) // 0 = free
			fat_free++;
		else
			fat_used++;
	}

	printf("fat_free_ratio=%zu/%u\n", fat_free, sb.data_count);

	// Root Directory Free Count
	size_t rdir_free = 0;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		if (root_dir[i].filename[0] == '\0') // Empty filename = unused entry
			rdir_free++;
	}

	printf("rdir_free_ratio=%zu/%d\n", rdir_free, FS_FILE_MAX_COUNT);

	return 0;
}

#define FAT_EOC 0xFFFF // Define end-of-chain marker

int fs_create(const char *filename)
{
	// Phase 2
}

int fs_delete(const char *filename)
{
	// Phase 2
}

int fs_ls(void)
{
	// Phase 2
}

// Phase 3

struct file_descriptor
{
	int used;		// Is this descriptor slot used?
	int root_index; // Index in root_dir[]
	size_t offset;	// Current file offset
};

static struct file_descriptor fd_table[FS_OPEN_MAX_COUNT];

int fs_open(const char *filename)
{
	if (!fs_mounted || filename == NULL)
		return -1;

	// Finds file in root directory
	int root_idx = -1;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
	{
		if (strncmp(root_dir[i].filename, filename, FS_FILENAME_LEN) == 0)
		{
			root_idx = i;
			break;
		}
	}

	if (root_idx == -1)
		return -1; // File not found

	// Finds a free slot in the fd_table
	for (int fd = 0; fd < FS_OPEN_MAX_COUNT; fd++)
	{
		if (fd_table[fd].used == 0)
		{
			fd_table[fd].used = 1;
			fd_table[fd].root_index = root_idx;
			fd_table[fd].offset = 0;
			return fd; 
		}
	}

	return -1; // Too many open files
}

int fs_close(int fd)
{
	// Ensures file system is mounted
	if (!fs_mounted)
		return -1;

	// Checks valid range
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT)
		return -1;

	// Checks if this descriptor is currently open
	if (!fd_table[fd].used)
		return -1;

	// Marks descriptor as unused
	fd_table[fd].used = 0;

	return 0;
}

int fs_stat(int fd)
{
	// Must be mounted
	if (!fs_mounted)
		return -1;

	// Valid range
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT)
		return -1;

	// Must be in use
	if (!fd_table[fd].used)
		return -1;

	// Gets size from root_dir entry
	int root_idx = fd_table[fd].root_index;
	return root_dir[root_idx].size;
}

int fs_lseek(int fd, size_t offset)
{
	// Checks if FS is mounted
	if (!fs_mounted)
		return -1;

	// Validates file descriptor range
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT)
		return -1;

	// Ensures fd is in use
	if (!fd_table[fd].used)
		return -1;

	// Checks if offset is within file size
	int root_idx = fd_table[fd].root_index;
	if (offset > root_dir[root_idx].size)
		return -1;

	// Updates offset
	fd_table[fd].offset = offset;

	return 0;
}

// Phase 4

// Helper Function
int find_free_fat_entry(void)
{
    for (int i = 0; i < sb.data_count; i++) {
        if (fat[i] == 0)  // 0 means free
            return i;
    }
    return -1;  // No free block
}

// Helper Function
int update_fat_chain(int current_index)
{
    int new_index = find_free_fat_entry();
    if (new_index == -1)
        return -1;

    fat[current_index] = new_index;
    fat[new_index] = FAT_EOC;

    return new_index;
}

// Helper Function
size_t write_to_block(int data_block_index, size_t offset, const uint8_t *src, size_t count)
{
    if (offset >= BLOCK_SIZE || count == 0 || offset + count > BLOCK_SIZE)
        return 0;  // Invalid range

    uint8_t block_buf[BLOCK_SIZE];

    if (block_read(sb.data_index + data_block_index, block_buf) < 0)
        return 0;

    memcpy(block_buf + offset, src, count);

    if (block_write(sb.data_index + data_block_index, block_buf) < 0)
        return 0;

    return count;
}

int fs_write(int fd, void *buf, size_t count)
{
    if (!fs_mounted || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].used || !buf)
        return -1;

    size_t written = 0;
    size_t offset = fd_table[fd].offset;
    int file_index = fd_table[fd].root_index;
    uint32_t file_size = root_dir[file_index].size;

    // Finds the start block
    int block_idx = root_dir[file_index].data_index;
    int prev_block = -1;

    // If the file has no data block yet, allocate one
    if (block_idx == FAT_EOC) {
        block_idx = find_free_fat_entry();
        if (block_idx == -1)
            return 0;
        fat[block_idx] = FAT_EOC;
        root_dir[file_index].data_index = block_idx;
    }

    // Traverses to the block corresponding to the offset
    int block_offset = offset / BLOCK_SIZE;
    int intra_offset = offset % BLOCK_SIZE;

    for (int i = 0; i < block_offset; i++) {
        prev_block = block_idx;
        if (fat[block_idx] == FAT_EOC) {
            int new_block = update_fat_chain(block_idx);
            if (new_block == -1) return written;
        }
        block_idx = fat[block_idx];
    }

    // Starts writing
    while (written < count) {
        // Allocates next block if at end of chain
        if (block_idx == FAT_EOC) {
            int new_block = update_fat_chain(prev_block);
            if (new_block == -1) break;
            block_idx = new_block;
        }

        size_t chunk = BLOCK_SIZE - intra_offset;
        if (chunk > count - written)
            chunk = count - written;

        // Writes chunk
        size_t result = write_to_block(block_idx, intra_offset, (uint8_t *)buf + written, chunk);
        if (result == 0) break;

        written += result;
        intra_offset = 0;

        prev_block = block_idx;
        block_idx = fat[block_idx];
    }

    // Updates file metadata
    fd_table[fd].offset += written;
    if (fd_table[fd].offset > file_size)
        root_dir[file_index].size = fd_table[fd].offset;

    // Writes FAT and root directory to disk
    for (int i = 0; i < sb.fat_blocks; i++)
        block_write(1 + i, (uint8_t *)fat + i * BLOCK_SIZE);

    block_write(sb.root_index, root_dir);

    return written;
}

int fs_read(int fd, void *buf, size_t count)
{
    if (!fs_mounted || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !fd_table[fd].used || !buf)
        return -1;

    size_t offset = fd_table[fd].offset;
    int file_index = fd_table[fd].root_index;
    uint32_t file_size = root_dir[file_index].size;

    if (offset >= file_size)
        return 0; // Nothing to read, at EOF

    size_t remaining = file_size - offset;
    size_t to_read = (count < remaining) ? count : remaining;
    size_t read_bytes = 0;

    int block_idx = root_dir[file_index].data_index;

    // Traverses FAT chain to the starting block
    int block_offset = offset / BLOCK_SIZE;
    int intra_offset = offset % BLOCK_SIZE;
    for (int i = 0; i < block_offset; i++) {
        if (block_idx == FAT_EOC)
            return 0;
        block_idx = fat[block_idx];
    }

    while (read_bytes < to_read && block_idx != FAT_EOC) {
        uint8_t block_buf[BLOCK_SIZE];
        if (block_read(sb.data_index + block_idx, block_buf) < 0)
            break;

        size_t chunk = BLOCK_SIZE - intra_offset;
        if (chunk > to_read - read_bytes)
            chunk = to_read - read_bytes;

        memcpy((uint8_t *)buf + read_bytes, block_buf + intra_offset, chunk);

        read_bytes += chunk;
        intra_offset = 0;
        block_idx = fat[block_idx];
    }

    fd_table[fd].offset += read_bytes;
    return read_bytes;
}