/*
 * Copyright (C) John Crispin <blogic@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.  */

#include "includes.h"
#include <endian.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lib/crypto/md4.h"

static void E_md4hash(const char *passwd, uchar p16[16])
{
	int len;
	smb_ucs2_t wpwd[129];
	int i;

	len = strlen(passwd);
	for (i = 0; i < len; i++) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		wpwd[i] = (unsigned char)passwd[i];
#else
		wpwd[i] = (unsigned char)passwd[i] << 8;
#endif
	}
	wpwd[i] = 0;

	len = len * sizeof(int16);
	mdfour(p16, (unsigned char *)wpwd, len);
	ZERO_STRUCT(wpwd);
}

/* returns -1 if user is not present in /etc/passwd*/
int find_uid_for_user(char *user)
{
	char t[256];
	FILE *fp = fopen("/etc/passwd", "r");
	int ret = -1;

	if(!fp)
	{
		printf("failed to open /etc/passwd\n");
		goto out;
	}

	while(!feof(fp))
	{
		if(fgets(t, 255, fp))
		{
			char *p1, *p2;
			p1 = strchr(t, ':');
			if(p1 && (p1 - t == strlen(user)) && (strncmp(t, user, strlen(user))) == 0)
			{
				p1 = strchr(t, ':');
				if(!p1)
					goto out;
				p2 = strchr(++p1, ':');
				if(!p2)
					goto out;
				p1 = strchr(++p2, ':');
				if(!p1)
					goto out;
				*p1 = '\0';
				ret = atoi(p2);
				goto out;
			}
		}
	}
	printf("No valid user found in /etc/passwd\n");

out:
	if(fp)
		fclose(fp);
	return ret;
}

static const char smbpasswd[] = "/etc/samba/smbpasswd";

static FILE *open_smbpasswd_file(int create)
{
	int fd, flags = O_RDWR | O_NOFOLLOW | O_NONBLOCK;
	struct stat st;
	FILE *fp;
	mode_t old_umask;

	if (create) {
		old_umask = umask(077);
		fd = open(smbpasswd, flags | O_CREAT | O_EXCL, 0600);
		umask(old_umask);
		if (fd == -1 && errno == EEXIST)
			fd = open(smbpasswd, flags);
	} else {
		fd = open(smbpasswd, flags);
	}
	if (fd == -1)
		return NULL;

	if (fstat(fd, &st) == -1)
		goto fail;
	if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1) {
		errno = EPERM;
		goto fail;
	}
	if (fchmod(fd, 0600) == -1)
		goto fail;

	fp = fdopen(fd, "r+");
	if (!fp)
		goto fail;
	return fp;

fail:
	close(fd);
	return NULL;
}

void insert_user_in_smbpasswd(char *user, char *line)
{
	char t[256];
	FILE *fp = open_smbpasswd_file(1);

	if(!fp)
	{
		printf("failed to open %s\n", smbpasswd);
		goto out;
	}

	while(!feof(fp))
	{
		if(fgets(t, 255, fp))
		{
			char *p;
			p = strchr(t, ':');
			if(p && (p - t == strlen(user)) && (strncmp(t, user, strlen(user))) == 0)
			{
				fseek(fp, -strlen(line), SEEK_CUR);
				break;
			}
		}
	}

	fprintf(fp, line);

out:
	if(fp)
		fclose(fp);
}

void delete_user_from_smbpasswd(char *user)
{
	char t[256];
	FILE *fp = open_smbpasswd_file(0);

	if(!fp)
	{
		printf("failed to open %s\n", smbpasswd);
		goto out;
	}

	while(!feof(fp))
	{
		if(fgets(t, 255, fp))
		{
			char *p;
			p = strchr(t, ':');
			if(p && (p - t == strlen(user)) && (strncmp(t, user, strlen(user))) == 0)
			{
#if defined(__GLIBC__) || defined(__UCLIBC__) /* not musl */
				fpos_t r_pos, w_pos;
				char t2[256];
				fgetpos(fp, &r_pos);
				w_pos = r_pos;
				w_pos.__pos -= strlen(t);
				while(fgets(t2, 256, fp))
				{
					fsetpos(fp, &w_pos);
					fputs(t2, fp);
					r_pos.__pos += strlen(t2);
					w_pos.__pos += strlen(t2);
					fsetpos(fp, &r_pos);
				}
				ftruncate(fileno(fp), w_pos.__pos);
#else
				long r_pos, w_pos;
				char t2[256];
				r_pos = ftell(fp);
				w_pos = r_pos;
				w_pos -= strlen(t);
				while(fgets(t2, 256, fp))
				{
					fseek(fp, w_pos, SEEK_SET);
					fputs(t2, fp);
					r_pos += strlen(t2);
					w_pos += strlen(t2);
					fseek(fp, r_pos, SEEK_SET);
				}
				ftruncate(fileno(fp), w_pos);
#endif
				break;
			}
		}
	}

out:
	if(fp)
		fclose(fp);
}

int main(int argc, char **argv)
{
	int uid;
	int ch;
	uchar new_nt_p16[NT_HASH_LEN];
	int g;
	char smbpasswd_line[256];
	char password[33];
	size_t password_length = 0;
	char *s;

	if(argc == 3 && strcmp(argv[1], "-del") == 0)
	{
		printf("deleting user %s\n", argv[2]);
		delete_user_from_smbpasswd(argv[2]);
		return 0;
	}
	if(argc != 2)
	{
		printf("usage for smbpasswd - \n\t%s USERNAME <password on stdin>\n\t%s -del USERNAME\n", argv[0], argv[0]);
		exit(1);
	}
	while ((ch = getchar()) != '\n' && ch != EOF)
	{
		if (password_length >= 32 || ch < 32 || ch > 126)
			exit(3);
		password[password_length++] = ch;
	}
	if (ch != '\n' || getchar() != EOF)
		exit(3);
	password[password_length] = '\0';

	uid = find_uid_for_user(argv[1]);
	if(uid <= 0)
		exit(2);

	E_md4hash(password, new_nt_p16);
	memset(password, 0, sizeof(password));
	s = smbpasswd_line;
	s += snprintf(s, 256 - (s - smbpasswd_line), "%s:%d:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:", argv[1], uid);
	for(g = 0; g < 16; g++)
		s += snprintf(s, 256 - (s - smbpasswd_line), "%02X", new_nt_p16[g]);
	snprintf(s, 256 - (s - smbpasswd_line), ":[U          ]:LCT-00000001:\n");

	insert_user_in_smbpasswd(argv[1], smbpasswd_line);

	return 0;
}
