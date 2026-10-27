/* vi: set sw=4 ts=4: */
/*
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

#include "libbb.h"
#include "bb_archive.h"

/* Symlinks created by this extraction; pre-existing ones (e.g. /etc -> tmp/etc) are trusted. */
static struct {
	dev_t dev;
	ino_t ino;
} *created_links;
static unsigned created_link_cnt;

static void remember_created_link(const char *name)
{
	struct stat st;

	if (lstat(name, &st) != 0 || !S_ISLNK(st.st_mode))
		return;
	created_links = xrealloc(created_links, (created_link_cnt + 1) * sizeof(*created_links));
	created_links[created_link_cnt].dev = st.st_dev;
	created_links[created_link_cnt].ino = st.st_ino;
	created_link_cnt++;
}

static int is_created_link(const struct stat *st)
{
	unsigned i;

	for (i = 0; i < created_link_cnt; i++) {
		if (created_links[i].dev == st->st_dev && created_links[i].ino == st->st_ino)
			return 1;
	}
	return 0;
}

static void check_extract_path(const char *name, int include_leaf)
{
	char *path = xstrdup(name);
	char *component = path;
	char *cursor;
	struct stat st;

	for (cursor = path; ; cursor++) {
		char saved = *cursor;
		if (saved != '/' && saved != '\0')
			continue;
		if (cursor - component == 2 && component[0] == '.' && component[1] == '.')
			bb_error_msg_and_die("unsafe archive path: %s", name);
		if (cursor != path && (saved == '/' || include_leaf)) {
			*cursor = '\0';
			if (lstat(path, &st) == 0) {
				if (S_ISLNK(st.st_mode) && is_created_link(&st))
					bb_error_msg_and_die("archive path traverses symlink: %s", name);
			} else if (errno != ENOENT) {
				bb_perror_msg_and_die("can't check archive path: %s", name);
			}
			*cursor = saved;
		}
		if (saved == '\0')
			break;
		component = cursor + 1;
	}
	free(path);
}

void FAST_FUNC data_extract_all(archive_handle_t *archive_handle)
{
	file_header_t *file_header = archive_handle->file_header;
	int dst_fd;
	int res;
	char *hard_link;
#if ENABLE_FEATURE_TAR_LONG_OPTIONS
	char *dst_name;
#else
# define dst_name (file_header->name)
#endif

#if ENABLE_FEATURE_TAR_SELINUX
	char *sctx = archive_handle->tar__sctx[PAX_NEXT_FILE];
	if (!sctx)
		sctx = archive_handle->tar__sctx[PAX_GLOBAL];
	if (sctx) { /* setfscreatecon is 4 syscalls, avoid if possible */
		setfscreatecon(sctx);
		free(archive_handle->tar__sctx[PAX_NEXT_FILE]);
		archive_handle->tar__sctx[PAX_NEXT_FILE] = NULL;
	}
#endif

	/* Hard links are encoded as regular files of size 0
	 * with a nonempty link field */
	hard_link = NULL;
	if (S_ISREG(file_header->mode) && file_header->size == 0)
		hard_link = file_header->link_target;

#if ENABLE_FEATURE_TAR_LONG_OPTIONS
	dst_name = file_header->name;
	if (archive_handle->tar__strip_components) {
		unsigned n = archive_handle->tar__strip_components;
		do {
			dst_name = strchr(dst_name, '/');
			if (!dst_name || dst_name[1] == '\0') {
				data_skip(archive_handle);
				goto ret;
			}
			dst_name++;
			/*
			 * Link target is shortened only for hardlinks:
			 * softlinks restored unchanged.
			 */
			if (hard_link) {
// GNU tar 1.26 does not check that we reached end of link name:
// if "dir/hardlink" is hardlinked to "file",
// tar xvf a.tar --strip-components=1 says:
//  tar: hardlink: Cannot hard link to '': No such file or directory
// and continues processing. We silently skip such entries.
				hard_link = strchr(hard_link, '/');
				if (!hard_link || hard_link[1] == '\0') {
					data_skip(archive_handle);
					goto ret;
				}
				hard_link++;
			}
		} while (--n != 0);
	}
#endif

	check_extract_path(dst_name, S_ISDIR(file_header->mode));
	if (hard_link) {
		if (hard_link[0] == '/')
			bb_error_msg_and_die("unsafe archive link: %s", hard_link);
		check_extract_path(hard_link, 1);
	}

	if (archive_handle->ah_flags & ARCHIVE_CREATE_LEADING_DIRS) {
		char *slash = strrchr(dst_name, '/');
		if (slash) {
			*slash = '\0';
			bb_make_directory(dst_name, -1, FILEUTILS_RECUR);
			*slash = '/';
		}
	}

	if (archive_handle->ah_flags & ARCHIVE_UNLINK_OLD) {
		/* Remove the entry if it exists */
		if (!S_ISDIR(file_header->mode)) {
			if (hard_link) {
				/* Ugly special case:
				 * tar cf t.tar hardlink1 hardlink2 hardlink1
				 * results in this tarball structure:
				 * hardlink1
				 * hardlink2 -> hardlink1
				 * hardlink1 -> hardlink1 <== !!!
				 */
				if (strcmp(hard_link, dst_name) == 0)
					goto ret;
			}
			/* Proceed with deleting */
			if (unlink(dst_name) == -1
			 && errno != ENOENT
			) {
				bb_perror_msg_and_die("can't remove old file %s",
						dst_name);
			}
		}
	}
	else if (archive_handle->ah_flags & ARCHIVE_EXTRACT_NEWER) {
		/* Remove the existing entry if its older than the extracted entry */
		struct stat existing_sb;
		if (lstat(dst_name, &existing_sb) == -1) {
			if (errno != ENOENT) {
				bb_perror_msg_and_die("can't stat old file");
			}
		}
		else if (existing_sb.st_mtime >= file_header->mtime) {
			if (!(archive_handle->ah_flags & ARCHIVE_EXTRACT_QUIET)
			 && !S_ISDIR(file_header->mode)
			) {
				bb_error_msg("%s not created: newer or "
					"same age file exists", dst_name);
			}
			data_skip(archive_handle);
			goto ret;
		}
		else if ((unlink(dst_name) == -1) && (errno != EISDIR)) {
			bb_perror_msg_and_die("can't remove old file %s",
					dst_name);
		}
	}

	/* Handle hard links separately */
	if (hard_link) {
		res = link(hard_link, dst_name);
		if (res == 0)
			remember_created_link(dst_name);
		if (res != 0 && !(archive_handle->ah_flags & ARCHIVE_EXTRACT_QUIET)) {
			bb_perror_msg("can't create %slink "
					"from %s to %s", "hard",
					dst_name,
					hard_link);
		}
		/* Hardlinks have no separate mode/ownership, skip chown/chmod */
		goto ret;
	}

	/* Create the filesystem entry */
	switch (file_header->mode & S_IFMT) {
	case S_IFREG: {
		/* Regular file */
		char *dst_nameN;
		int flags = O_WRONLY | O_CREAT | O_EXCL;
		if (archive_handle->ah_flags & ARCHIVE_O_TRUNC)
			flags = O_WRONLY | O_CREAT | O_TRUNC;
		flags |= O_NOFOLLOW;
		dst_nameN = dst_name;
#ifdef ARCHIVE_REPLACE_VIA_RENAME
		if (archive_handle->ah_flags & ARCHIVE_REPLACE_VIA_RENAME)
			/* rpm-style temp file name */
			dst_nameN = xasprintf("%s;%x", dst_name, (int)getpid());
#endif
		dst_fd = xopen3(dst_nameN,
			flags,
			file_header->mode
			);
		bb_copyfd_exact_size(archive_handle->src_fd, dst_fd, file_header->size);
		close(dst_fd);
#ifdef ARCHIVE_REPLACE_VIA_RENAME
		if (archive_handle->ah_flags & ARCHIVE_REPLACE_VIA_RENAME) {
			xrename(dst_nameN, dst_name);
			free(dst_nameN);
		}
#endif
		break;
	}
	case S_IFDIR:
		res = mkdir(dst_name, file_header->mode);
		if ((res == -1)
		 && (errno != EISDIR) /* btw, Linux doesn't return this */
		 && (errno != EEXIST)
		 && !(archive_handle->ah_flags & ARCHIVE_EXTRACT_QUIET)
		) {
			bb_perror_msg("can't make dir %s", dst_name);
		}
		break;
	case S_IFLNK:
		/* Symlink */
//TODO: what if file_header->link_target == NULL (say, corrupted tarball?)
		res = symlink(file_header->link_target, dst_name);
		if (res == 0)
			remember_created_link(dst_name);
		if (res != 0
		 && !(archive_handle->ah_flags & ARCHIVE_EXTRACT_QUIET)
		) {
			bb_perror_msg("can't create %slink "
				"from %s to %s", "sym",
				dst_name,
				file_header->link_target);
		}
		break;
	case S_IFSOCK:
	case S_IFBLK:
	case S_IFCHR:
	case S_IFIFO:
		res = mknod(dst_name, file_header->mode, file_header->device);
		if ((res == -1)
		 && !(archive_handle->ah_flags & ARCHIVE_EXTRACT_QUIET)
		) {
			bb_perror_msg("can't create node %s", dst_name);
		}
		break;
	default:
		bb_error_msg_and_die("unrecognized file type");
	}

	if (!S_ISLNK(file_header->mode)) {
		if (!(archive_handle->ah_flags & ARCHIVE_DONT_RESTORE_OWNER)) {
			uid_t uid = file_header->uid;
			gid_t gid = file_header->gid;
#if ENABLE_FEATURE_TAR_UNAME_GNAME
			if (!(archive_handle->ah_flags & ARCHIVE_NUMERIC_OWNER)) {
				if (file_header->tar__uname) {
//TODO: cache last name/id pair?
					struct passwd *pwd = getpwnam(file_header->tar__uname);
					if (pwd) uid = pwd->pw_uid;
				}
				if (file_header->tar__gname) {
					struct group *grp = getgrnam(file_header->tar__gname);
					if (grp) gid = grp->gr_gid;
				}
			}
#endif
			/* GNU tar 1.15.1 uses chown, not lchown */
			chown(dst_name, uid, gid);
		}
		/* uclibc has no lchmod, glibc is even stranger -
		 * it has lchmod which seems to do nothing!
		 * so we use chmod... */
		if (!(archive_handle->ah_flags & ARCHIVE_DONT_RESTORE_PERM)) {
			chmod(dst_name, file_header->mode);
		}
		if (archive_handle->ah_flags & ARCHIVE_RESTORE_DATE) {
			struct timeval t[2];

			t[1].tv_sec = t[0].tv_sec = file_header->mtime;
			t[1].tv_usec = t[0].tv_usec = 0;
			utimes(dst_name, t);
		}
	}

 ret: ;
#if ENABLE_FEATURE_TAR_SELINUX
	if (sctx) {
		/* reset the context after creating an entry */
		setfscreatecon(NULL);
	}
#endif
}
