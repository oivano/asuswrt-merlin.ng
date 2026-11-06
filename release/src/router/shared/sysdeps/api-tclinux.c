#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include "shutils.h"
#include "shared.h"

static int crc_table_empty = 1;
static unsigned long crc_table[256];

#define SWAP_LONG(x) \
	((u_int32_t)( \
		(((u_int32_t)(x) & (u_int32_t)0x000000ffUL) << 24) | \
		(((u_int32_t)(x) & (u_int32_t)0x0000ff00UL) <<  8) | \
		(((u_int32_t)(x) & (u_int32_t)0x00ff0000UL) >>  8) | \
		(((u_int32_t)(x) & (u_int32_t)0xff000000UL) >> 24) ))

#define DO1(buf) crc = crc_table[((int)crc ^ (*buf++)) & 0xff] ^ (crc >> 8);
#define DO2(buf)  DO1(buf); DO1(buf);
#define DO4(buf)  DO2(buf); DO2(buf);
#define DO8(buf)  DO4(buf); DO4(buf);

#define TC_HDR_LEN	0x100
#define TC_ROUTER_HEADER_LEN 8

static void make_crc_table()
{
	unsigned long c;
	int n, k;
	unsigned long poly;	    /* polynomial exclusive-or pattern */
	/* terms of polynomial defining this crc (except x^32): */
	static const unsigned char p[] = {0,1,2,4,5,7,8,10,11,12,16,22,23,26};

	/* make exclusive-or pattern from polynomial (0xedb88320L) */
	poly = 0L;
	for (n = 0; n < sizeof(p)/sizeof(unsigned char); n++)
		poly |= 1L << (31 - p[n]);

	for (n = 0; n < 256; n++)
	{
		c = (unsigned long)n;
		for (k = 0; k < 8; k++)
			c = c & 1 ? poly ^ (c >> 1) : c >> 1;
		crc_table[n] = c;
	}
	crc_table_empty = 0;
}

unsigned long crc32_no_comp(unsigned long crc,const unsigned char* buf, int len)
{
	if (crc_table_empty)
		make_crc_table();

	while (len >= 8)
	{
		DO8(buf);
		len -= 8;
	}
	if (len) do {
		DO1(buf);
	} while (--len);

	return crc;
}

#ifdef RTCONFIG_RALINK
int separate_tc_fw_from_trx(char* trxpath)
{
	FILE* FpTrx;
	char TrxHdrBuf[512] = {0};
	char buf[4096] = {0};
	unsigned int *pTrxSize;
	unsigned int TrxSize = 0;
	unsigned int filelen;
	unsigned int TcFwSize;
	int RetVal = 0;
	size_t len_trxhdrbuf = 0;
	size_t r_counts = 0;
	size_t w_counts = 0;
	size_t buf_size = sizeof(buf);
	size_t TrxHdrBuf_size = sizeof(TrxHdrBuf);

	FILE* fpSrc = NULL;
	FILE* fpDst = NULL;

	FpTrx = fopen(trxpath, "rb");
	if (FpTrx == NULL)
	{
		goto err;
	}

	len_trxhdrbuf = fread(TrxHdrBuf,1,TrxHdrBuf_size,FpTrx);
	if(len_trxhdrbuf == TrxHdrBuf_size)
	{
		fseek( FpTrx, 0, SEEK_END);
		filelen = ftell( FpTrx );
		fclose(FpTrx);
	}
	else
	{
		cprintf("Cannot read trx file[%40s] correctly!!\n", trxpath);
		fclose(FpTrx);
		goto err;
	}
	pTrxSize = (unsigned int*)(TrxHdrBuf+4);	//bcm
	TrxSize = *pTrxSize;
	cprintf("trx size %u, file size %u\n", TrxSize, filelen);
	if (filelen > TrxSize)
	{
		TcFwSize = filelen - TrxSize;
		cprintf("tcfw size %u\n",TcFwSize);

		if (TcFwSize > TC_HDR_LEN)
		{
			fpSrc = fopen(trxpath, "rb");
			if (fpSrc==NULL) goto err;
			fpDst = fopen("/tmp/tcfw.bin", "wb");
			if (fpDst==NULL) goto err;

			fseek(fpSrc, TrxSize, SEEK_SET);

			r_counts = fread(buf, 1, TC_HDR_LEN, fpSrc);
			if(r_counts == TC_HDR_LEN)
			{
				w_counts = fwrite(buf, 1, TC_HDR_LEN, fpDst);
				if(w_counts == TC_HDR_LEN)
				{
					TcFwSize -= TC_HDR_LEN;
				}
				else
				{
					goto err;
				}
			}
			else
			{
				goto err;
			}

			cprintf("tcfw magic : %c%c%c%c\n",buf[0],buf[1],buf[2],buf[3]);
			if (strncmp(&buf[0], "2RDH", 4))
				goto err;

			while (TcFwSize > 0)
			{
				if (TcFwSize > buf_size)
				{
					r_counts = fread(buf, 1, buf_size, fpSrc);
					if(r_counts == buf_size)
					{
						w_counts = fwrite(buf, 1, buf_size, fpDst);
						if(w_counts == buf_size)
						{
							TcFwSize -= buf_size;
						}
						else
						{
							goto err;
						}
					}
					else
					{
						goto err;
					}
				}
				else
				{
					r_counts = fread(buf, 1, TcFwSize, fpSrc);
					if(r_counts == TcFwSize)
					{
						w_counts = fwrite(buf, 1, TcFwSize, fpDst);
						if(w_counts == TcFwSize)
						{
							TcFwSize = 0;
						}
						else
						{
							goto err;
						}
					}
					else
					{
						goto err;
					}
				}
			}
		}
		else {
			cprintf("not tc fw\n");
			goto err;
		}
	}
	else if (TrxSize == filelen)
	{
		// only trx, no tc fw
		printf("no tc fw\n");
		goto err;
	}

	RetVal = 1;

err:
	if(TrxSize)
		truncate(trxpath, TrxSize);

	if (fpSrc)
		fclose(fpSrc);

	if (fpDst)
		fclose(fpDst);

	return RetVal;
}

int check_tc_firmware_crc()
{
	FILE* fpSrc = NULL;
	FILE* fpDst = NULL;
	unsigned long* crc_value_ptr = NULL;
	unsigned long ulfw_crc = 0, calc_crc = 0;
	unsigned long trxlen, *trxlenptr;
	int skip_flag = 0;
	int RetVal = 0;
	char buf[4096] = {0};
	size_t r_counts = 0;
	size_t w_counts = 0;
	size_t buf_size = sizeof(buf);
	struct stat st;

	fpSrc = fopen("/tmp/tcfw.bin", "rb");
	if (fpSrc==NULL)
	{
		skip_flag = 1;
		goto exit;
	}
	fpDst = fopen("/tmp/tclinux.bin", "wb");
	if (fpDst==NULL)
	{
		skip_flag = 1;
		goto exit;
	}

	r_counts = fread(buf, 1, 0x100, fpSrc);
	if(r_counts == 0x100)
	{
		trxlenptr=(unsigned long*)(buf+8);
		trxlen=*trxlenptr;
		trxlen=SWAP_LONG(trxlen);
		cprintf("tcfw len: %lu\n", trxlen);
	}
	else
	{
		goto exit;
	}

	w_counts = fwrite(buf, 1, 0x100, fpDst);
	if(w_counts == 0x100)
	{
		trxlen -= 0x100;
	}
	else
	{
		goto exit;
	}

	crc_value_ptr=(unsigned long*)(buf+12);
	ulfw_crc=*crc_value_ptr;
	ulfw_crc=SWAP_LONG(ulfw_crc);
	cprintf("ulfw crc: %lx\n", ulfw_crc);

	calc_crc = 0xffffffff;

	while(trxlen>0)
	{
		if (trxlen > buf_size)
		{
			r_counts = fread(buf, 1, buf_size, fpSrc);
			if(r_counts == buf_size)
			{
				w_counts = fwrite(buf, 1, buf_size, fpDst);
				if(w_counts == buf_size)
				{
					calc_crc = crc32_no_comp(calc_crc, (unsigned char*)buf, buf_size);
					trxlen -= buf_size;
				}
				else
				{
					goto exit;
				}
			}
			else
			{
				goto exit;
			}
		}
		else
		{
			r_counts = fread(buf, 1, trxlen, fpSrc);
			if(r_counts == trxlen)
			{
				w_counts = fwrite(buf, 1, trxlen, fpDst);
				if(w_counts == trxlen)
				{
					calc_crc = crc32_no_comp(calc_crc, (unsigned char*)buf, trxlen);
					trxlen=0;
				}
				else
				{
					goto exit;
				}
			}
			else
			{
				goto exit;
			}
		}
	}

	cprintf("calc crc: %lx\n", calc_crc);
	fflush(fpDst);

	stat("/tmp/tclinux.bin", &st);
	cprintf("size of /tmp/tclinux.bin: %d\n", st.st_size);

	if (ulfw_crc != calc_crc)
			skip_flag = 1;
#ifdef RTCONFIG_BRCM_NAND_JFFS2
	else {
		cprintf("backup tclinux\n");
		unlink("/jffs/tclinux.bin");
		eval("cp", "-f", "/tmp/tclinux.bin", "/jffs/tclinux.bin");
	}
#endif

	unlink("/tmp/tcfw.bin");


	cprintf("check tcfw done\n");

exit:

	if(skip_flag)
		RetVal = -1;

	if (fpSrc)
		fclose(fpSrc);

	if (fpDst)
		fclose(fpDst);

	return RetVal;
}
#endif

#define TC_FW_HTTPD_DIRECTORY "/tmp/httpd-upgrade"
#define TC_FW_IMAGE_NAME "tclinux.bin"
#define TC_FW_PART_NAME "tcfw.bin"

static int
tc_stage_directory_open(const char *path)
{
	int fd;
	struct stat st;

	if (geteuid() != 0)
		return -1;
	fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
	    (st.st_mode & 0777) != 0700) {
		close(fd);
		return -1;
	}
	return fd;
}

static int
tc_stage_file_open(int dirfd, const char *name, int create)
{
	int flags = create ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY | O_NONBLOCK;
	int fd;
	struct stat st;

	fd = openat(dirfd, name, flags | O_NOFOLLOW, 0600);
	if (fd < 0)
		return -1;
	if ((create && fchmod(fd, 0600) != 0) || fstat(fd, &st) != 0 ||
	    !S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_nlink != 1 ||
	    (st.st_mode & 0777) != 0600) {
		close(fd);
		if (create)
			unlinkat(dirfd, name, 0);
		return -1;
	}
	return fd;
}

static int
tc_read_exact_at(int fd, void *buffer, size_t length, off_t offset)
{
	char *next = buffer;
	size_t done = 0;

	while (done < length) {
		ssize_t count = pread(fd, next + done, length - done, offset + done);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		done += count;
	}
	return 0;
}

static int
tc_write_all(int fd, const void *buffer, size_t length)
{
	const char *next = buffer;
	size_t done = 0;

	while (done < length) {
		ssize_t count = write(fd, next + done, length - done);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		done += count;
	}
	return 0;
}

#ifdef RTCONFIG_BRCM_NAND_JFFS2
static int
tc_backup_firmware(int stagedirfd)
{
	int sourcefd = -1, jffsfd = -1, destfd = -1, result = -1, renamed = 0;
	int name_len;
	char temporary[64] = {0};
	unsigned char buffer[4096];
	off_t offset = 0;
	struct stat source, directory, destination;

	sourcefd = tc_stage_file_open(stagedirfd, TC_FW_IMAGE_NAME, 0);
	if (sourcefd < 0 || fstat(sourcefd, &source) != 0)
		goto done;
	jffsfd = open("/jffs", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (jffsfd < 0 || fstat(jffsfd, &directory) != 0 || !S_ISDIR(directory.st_mode) ||
	    directory.st_uid != 0 || (directory.st_mode & 0022) != 0)
		goto done;
	name_len = snprintf(temporary, sizeof(temporary), ".tclinux.bin.%ld", (long)getpid());
	if (name_len < 0 || (size_t)name_len >= sizeof(temporary))
		goto done;
	destfd = openat(jffsfd, temporary,
		O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
	if (destfd < 0 || fchmod(destfd, 0600) != 0 || fstat(destfd, &destination) != 0 ||
	    !S_ISREG(destination.st_mode) || destination.st_uid != 0 ||
	    destination.st_nlink != 1 || (destination.st_mode & 0777) != 0600)
		goto done;
	while (offset < source.st_size) {
		size_t count = source.st_size - offset > sizeof(buffer) ?
			sizeof(buffer) : source.st_size - offset;
		if (tc_read_exact_at(sourcefd, buffer, count, offset) != 0 ||
		    tc_write_all(destfd, buffer, count) != 0)
			goto done;
		offset += count;
	}
	if (fsync(destfd) != 0 || fstat(destfd, &destination) != 0 ||
	    destination.st_size != source.st_size)
		goto done;
	if (close(destfd) != 0) {
		destfd = -1;
		goto done;
	}
	destfd = -1;
	if (renameat(jffsfd, temporary, jffsfd, "tclinux.bin") != 0)
		goto done;
	renamed = 1;
	if (fsync(jffsfd) != 0)
		goto done;
	result = 0;

done:
	if (destfd >= 0)
		close(destfd);
	if (jffsfd >= 0) {
		if (!renamed && temporary[0])
			unlinkat(jffsfd, temporary, 0);
		close(jffsfd);
	}
	if (sourcefd >= 0)
		close(sourcefd);
	return result;
}
#endif

static int
tc_firmware_fd_valid(int fd, unsigned long *header_crc, off_t *firmware_size,
		     struct stat *identity)
{
	unsigned char header[TC_HDR_LEN];
	unsigned char buffer[4096];
	unsigned long payload_len, expected_crc, calculated_crc = 0xffffffff;
	u_int32_t value;
	off_t offset = TC_HDR_LEN, firmware_len;
	size_t count;
	struct stat after;

	if (fstat(fd, identity) != 0 || !S_ISREG(identity->st_mode) ||
	    identity->st_uid != 0 || identity->st_nlink != 1 ||
	    (identity->st_mode & 0777) != 0600 || identity->st_size <= TC_HDR_LEN ||
	    tc_read_exact_at(fd, header, sizeof(header), 0) != 0 ||
	    memcmp(header, "2RDH", 4) != 0)
		return -1;

	memcpy(&value, header + 8, sizeof(value));
	payload_len = SWAP_LONG(value);
	memcpy(&value, header + 12, sizeof(value));
	expected_crc = SWAP_LONG(value);
	if (payload_len <= TC_HDR_LEN || payload_len > (unsigned long)identity->st_size ||
	    payload_len > 0x7fffffffUL)
		return -1;
	firmware_len = payload_len;

	while (offset < firmware_len) {
		count = firmware_len - offset > sizeof(buffer) ?
			sizeof(buffer) : firmware_len - offset;
		if (tc_read_exact_at(fd, buffer, count, offset) != 0)
			return -1;
		calculated_crc = crc32_no_comp(calculated_crc, buffer, count);
		offset += count;
	}
	if (calculated_crc != expected_crc || fstat(fd, &after) != 0 ||
	    after.st_dev != identity->st_dev || after.st_ino != identity->st_ino ||
	    after.st_size != identity->st_size)
		return -1;
	if (header_crc)
		*header_crc = expected_crc;
	if (firmware_size)
		*firmware_size = firmware_len;
	return 0;
}

int
stage_tc_firmware_from_trx(char *trxpath, long uploaded_len, const char *stage_dir,
			   int truncate_image)
{
	unsigned char trx_header[TC_ROUTER_HEADER_LEN];
	unsigned char buffer[4096];
	u_int32_t router_size;
	off_t file_size, router_len, remaining;
	int dirfd = -1, srcfd = -1, dstfd = -1, created = 0;
	struct stat source;

	if (!trxpath || !stage_dir || (truncate_image && geteuid() != 0))
		return -1;
	dirfd = tc_stage_directory_open(stage_dir);
	if (dirfd < 0)
		goto fail;
	srcfd = open(trxpath, (truncate_image ? O_RDWR : O_RDONLY) | O_NOFOLLOW | O_NONBLOCK);
	if (srcfd < 0 || fstat(srcfd, &source) != 0 || !S_ISREG(source.st_mode) ||
	    source.st_size < sizeof(trx_header) ||
	    (truncate_image && (source.st_uid != 0 || source.st_nlink != 1 ||
	     (source.st_mode & 0777) != 0600)) ||
	    (uploaded_len >= 0 && source.st_size != uploaded_len) ||
	    tc_read_exact_at(srcfd, trx_header, sizeof(trx_header), 0) != 0)
		goto fail;

	memcpy(&router_size, trx_header + 4, sizeof(router_size));
	file_size = source.st_size;
	if (router_size < 0x1c || router_size > file_size)
		goto fail;
	router_len = router_size;
	if (router_len == file_size) {
		close(srcfd);
		close(dirfd);
		return 0;
	}
	remaining = file_size - router_len;
	if (remaining <= TC_HDR_LEN)
		goto fail;
	if (lseek(srcfd, router_len, SEEK_SET) != router_len)
		goto fail;
	dstfd = tc_stage_file_open(dirfd, TC_FW_PART_NAME, 1);
	if (dstfd < 0)
		goto fail;
	created = 1;
	while (remaining > 0) {
		size_t count = remaining > sizeof(buffer) ? sizeof(buffer) : remaining;
		if (read(srcfd, buffer, count) != (ssize_t)count ||
		    tc_write_all(dstfd, buffer, count) != 0)
			goto fail;
		remaining -= count;
	}
	if (fsync(dstfd) != 0 || close(dstfd) != 0)
		goto fail;
	dstfd = -1;
	if (truncate_image && ftruncate(srcfd, router_len) != 0)
		goto fail;
	close(srcfd);
	close(dirfd);
	return 1;

fail:
	if (dstfd >= 0)
		close(dstfd);
	if (created && dirfd >= 0)
		unlinkat(dirfd, TC_FW_PART_NAME, 0);
	if (srcfd >= 0)
		close(srcfd);
	if (dirfd >= 0)
		close(dirfd);
	return -1;
}

int
check_tc_firmware_stage(const char *stage_dir, int keep_image)
{
	int dirfd = -1, srcfd = -1, dstfd = -1, result = -1, created = 0;
	struct stat source, output;
	unsigned char buffer[4096];
	off_t offset = 0, firmware_len;

	dirfd = tc_stage_directory_open(stage_dir);
	if (dirfd < 0)
		goto done;
	srcfd = tc_stage_file_open(dirfd, TC_FW_PART_NAME, 0);
	if (srcfd < 0 || tc_firmware_fd_valid(srcfd, NULL, &firmware_len, &source) != 0)
		goto done;
	if (keep_image) {
		dstfd = tc_stage_file_open(dirfd, TC_FW_IMAGE_NAME, 1);
		if (dstfd < 0)
			goto done;
		created = 1;
		while (offset < firmware_len) {
			size_t count = firmware_len - offset > sizeof(buffer) ?
				sizeof(buffer) : firmware_len - offset;
			if (tc_read_exact_at(srcfd, buffer, count, offset) != 0 ||
			    tc_write_all(dstfd, buffer, count) != 0)
				goto done;
			offset += count;
		}
		if (fsync(dstfd) != 0 || fstat(dstfd, &output) != 0 ||
		    !S_ISREG(output.st_mode) || output.st_uid != 0 || output.st_nlink != 1 ||
		    (output.st_mode & 0777) != 0600 || output.st_size != firmware_len)
			goto done;
#ifdef RTCONFIG_BRCM_NAND_JFFS2
#endif
	}
	result = 0;

done:
	if (dstfd >= 0 && close(dstfd) != 0)
		result = -1;
	if (srcfd >= 0)
		close(srcfd);
	if (dirfd >= 0) {
		unlinkat(dirfd, TC_FW_PART_NAME, 0);
		if (result != 0 && created)
			unlinkat(dirfd, TC_FW_IMAGE_NAME, 0);
		close(dirfd);
	}
	return result;
}

int
check_tc_firmware_image(char *trxpath)
{
	char stage_dir[] = "/tmp/tc-check-XXXXXX";
	int staged, result = -1;
	if (!mkdtemp(stage_dir))
		return -1;
	if (chmod(stage_dir, 0700) != 0) {
		rmdir(stage_dir);
		return -1;
	}
	staged = stage_tc_firmware_from_trx(trxpath, -1, stage_dir, 0);
	if (staged >= 0)
		result = staged ? check_tc_firmware_stage(stage_dir, 0) : 0;
	{
		int dirfd = tc_stage_directory_open(stage_dir);
		if (dirfd >= 0) {
			unlinkat(dirfd, TC_FW_PART_NAME, 0);
			unlinkat(dirfd, TC_FW_IMAGE_NAME, 0);
			close(dirfd);
		}
	}
	rmdir(stage_dir);
	return result;
}

static int
tc_upgrade_spool_published(int dirfd)
{
	int imagefd = -1, identityfd = -1, valid = 0;
	char identity[96];
	ssize_t count;
	unsigned long long device, inode, size;
	char trailing;
	struct stat image, identity_file;

	imagefd = openat(dirfd, "linux.trx", O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
	identityfd = openat(dirfd, "identity", O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
	if (imagefd < 0 || identityfd < 0 || fstat(imagefd, &image) != 0 ||
	    !S_ISREG(image.st_mode) || image.st_uid != 0 || image.st_nlink != 1 ||
	    (image.st_mode & 0777) != 0600 || fstat(identityfd, &identity_file) != 0 ||
	    !S_ISREG(identity_file.st_mode) || identity_file.st_uid != 0 ||
	    identity_file.st_nlink != 1 || (identity_file.st_mode & 0777) != 0600 ||
	    identity_file.st_size <= 0 || identity_file.st_size >= sizeof(identity))
		goto done;
	count = read(identityfd, identity, sizeof(identity) - 1);
	if (count <= 0)
		goto done;
	identity[count] = '\0';
	if (sscanf(identity, "%llu %llu %llu%c", &device, &inode, &size, &trailing) != 3)
		goto done;
	valid = device == (unsigned long long)image.st_dev &&
		inode == (unsigned long long)image.st_ino &&
		size == (unsigned long long)image.st_size;

done:
	if (imagefd >= 0)
		close(imagefd);
	if (identityfd >= 0)
		close(identityfd);
	return valid;
}

void do_upgrade_adsldrv(void)
{
	char ipaddr[80] = {0};
	FILE *fp;
	int dirfd = -1, fwfd = -1, ret, force_flag = 0;
	unsigned long old_crc = 0, new_crc = 0;
	u_int32_t value;
	struct stat fw_stat;

	cprintf("%s\n", __FUNCTION__);
	dirfd = tc_stage_directory_open(TC_FW_HTTPD_DIRECTORY);
	if (dirfd < 0 || !tc_upgrade_spool_published(dirfd))
		goto done;
	fwfd = tc_stage_file_open(dirfd, TC_FW_IMAGE_NAME, 0);
	if (fwfd < 0 || tc_firmware_fd_valid(fwfd, &new_crc, NULL, &fw_stat) != 0)
		goto done;
#ifdef RTCONFIG_BRCM_NAND_JFFS2
	if (tc_backup_firmware(dirfd) != 0)
		goto done;
#endif

	fp = fopen("/tmp/adsl/tc_ip_addr.txt", "r");
	if (fp) {
		if (!fgets(ipaddr, sizeof(ipaddr), fp)) {
			fclose(fp);
			goto done;
		}
		fclose(fp);
		ipaddr[strcspn(ipaddr, "\r\n")] = '\0';
		if (!ipaddr[0])
			goto done;
	}
	else {
		snprintf(ipaddr, sizeof(ipaddr), "169.254.0.1");
		force_flag = 1;
	}

	fp = fopen("/tmp/adsl/tc_hdr.bin", "rb");
	if (fp) {
		if (fseek(fp, 12L, SEEK_SET) != 0 || fread(&value, 1, sizeof(value), fp) != sizeof(value)) {
			fclose(fp);
			goto done;
		}
		old_crc = SWAP_LONG(value);
		fclose(fp);
		cprintf("old crc: %lx\n", old_crc);
	}
	cprintf("new crc: %lx\n", new_crc);
	if (old_crc && new_crc && new_crc == old_crc) {
		cprintf("Skip upgrade tc firmware\n");
		goto done;
	}

	if (force_flag)
		killall("tp_init", SIGKILL);
	else {
		eval("adslate", "waitadsl");
		eval("adslate", "quitdrv");
	}
	eval("iptables", "-I", "INPUT", "-p", "udp", "-j", "ACCEPT");
	eval("ifconfig", "vlan2", "169.254.10.10");
	eval("route", "add", "-host", ipaddr, "vlan2");
	cprintf("Start to upgrade tc fw\n");
	ret = eval("tftp", "-p", "-l", TC_FW_HTTPD_DIRECTORY "/" TC_FW_IMAGE_NAME, ipaddr);
	if (ret)
		cprintf("tftp failed\n");
	else
		cprintf("tftp done\n");
	eval("iptables", "-D", "INPUT", "-p", "udp", "-j", "ACCEPT");

done:
	if (fwfd >= 0)
		close(fwfd);
	if (dirfd >= 0) {
		unlinkat(dirfd, TC_FW_IMAGE_NAME, 0);
		close(dirfd);
	}
}
