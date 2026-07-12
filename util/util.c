/*
 * Taken from perf which in turn take it from GIT
 */
#include <stdio.h>

#include "kvm/util.h"

#include <kvm/kvm.h>
#include <linux/kvm.h>
#include <linux/magic.h>	/* For HUGETLBFS_MAGIC */
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>

static void report(const char *prefix, const char *err, va_list params)
{
	char msg[1024];
	vsnprintf(msg, sizeof(msg), err, params);
	fprintf(stderr, " %s%s\n", prefix, msg);
}

static NORETURN void die_builtin(const char *err, va_list params)
{
	report(" Fatal: ", err, params);
	exit(128);
}

static void error_builtin(const char *err, va_list params)
{
	report(" Error: ", err, params);
}

static void warn_builtin(const char *warn, va_list params)
{
	report(" Warning: ", warn, params);
}

static void info_builtin(const char *info, va_list params)
{
	report(" Info: ", info, params);
}

static void debug_builtin(const char *debug, va_list params)
{
	report(" Debug: ", debug, params);
}

void die(const char *err, ...)
{
	va_list params;

	va_start(params, err);
	die_builtin(err, params);
	va_end(params);
}

void pr_err(const char *err, ...)
{
	va_list params;

	if (loglevel < LOGLEVEL_ERROR)
		return;

	va_start(params, err);
	error_builtin(err, params);
	va_end(params);
}

void pr_warning(const char *warn, ...)
{
	va_list params;

	if (loglevel < LOGLEVEL_WARNING)
		return;

	va_start(params, warn);
	warn_builtin(warn, params);
	va_end(params);
}

void pr_info(const char *info, ...)
{
	va_list params;

	if (loglevel < LOGLEVEL_INFO)
		return;

	va_start(params, info);
	info_builtin(info, params);
	va_end(params);
}

/* Do not call directly; call pr_debug() instead. */
void __pr_debug(const char *debug, ...)
{
	va_list params;

	va_start(params, debug);
	debug_builtin(debug, params);
	va_end(params);
}

void die_perror(const char *fmt, ...)
{
	char buf[1024];
	va_list params;
	int e = errno;
	int ret;

	va_start(params, fmt);
	ret = vsnprintf(buf, sizeof(buf), fmt, params);
	if (ret < 0) {
		perror("vsnprintf");
		buf[0] = '\0';
	}
	va_end(params);

	errno = e;
	perror(buf);
	exit(e);
}

void *mmap_hugetlbfs(struct kvm *kvm, const char *htlbfs_path, u64 size)
{
	char mpath[PATH_MAX];
	int fd;
	struct statfs sfs;
	void *addr;
	unsigned long blk_size;

	if (statfs(htlbfs_path, &sfs) < 0)
		die("Can't stat %s", htlbfs_path);

	if ((unsigned int)sfs.f_type != HUGETLBFS_MAGIC)
		die("%s is not hugetlbfs!", htlbfs_path);

	blk_size = (unsigned long)sfs.f_bsize;
	if (sfs.f_bsize == 0 || blk_size > size) {
		die("Can't use hugetlbfs pagesize %ld for mem size %lld",
			blk_size, (unsigned long long)size);
	}

	kvm->ram_pagesize = blk_size;

	snprintf(mpath, PATH_MAX, "%s/kvmtoolXXXXXX", htlbfs_path);
	fd = mkstemp(mpath);
	if (fd < 0)
		die("Can't open %s for hugetlbfs map", mpath);
	unlink(mpath);
	if (ftruncate(fd, size) < 0)
		die("Can't ftruncate for mem mapping size %lld",
			(unsigned long long)size);
	addr = mmap(NULL, size, PROT_RW, MAP_PRIVATE, fd, 0);
	close(fd);

	return addr;
}

/* This function wraps the decision between hugetlbfs map (if requested) or normal mmap */
void *mmap_anon_or_hugetlbfs(struct kvm *kvm, const char *hugetlbfs_path, u64 size)
{
	if (hugetlbfs_path)
		/*
		 * We don't /need/ to map guest RAM from hugetlbfs, but we do so
		 * if the user specifies a hugetlbfs path.
		 */
		return mmap_hugetlbfs(kvm, hugetlbfs_path, size);
	else {
		kvm->ram_pagesize = getpagesize();
		return mmap(NULL, size, PROT_RW, MAP_ANON_NORESERVE, -1, 0);
	}
}

/*
 * Map guest RAM backed by a guest_memfd. The file descriptor is kept open
 * until teardown (kvm__arch_delete_ram), after the mapping is removed.
 */
void *mmap_guest_memfd(struct kvm *kvm, u64 size)
{
	u64 flags = GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_INIT_SHARED;
	struct kvm_create_guest_memfd gmem = {
		.size	= size,
		.flags	= flags,
	};
	void *addr;
	int ret;

	if (!kvm__supports_extension(kvm, KVM_CAP_GUEST_MEMFD))
		die("kernel does not support guest_memfd");

	ret = ioctl(kvm->vm_fd, KVM_CHECK_EXTENSION, KVM_CAP_GUEST_MEMFD_FLAGS);
	if (ret < 0 || ((u64)ret & flags) != flags)
		die("VM type does not support guest_memfd with mmap");

	ret = ioctl(kvm->vm_fd, KVM_CREATE_GUEST_MEMFD, &gmem);
	if (ret < 0)
		die_perror("KVM_CREATE_GUEST_MEMFD");

	addr = mmap(NULL, size, PROT_RW, MAP_SHARED, ret, 0);
	if (addr == MAP_FAILED)
		die_perror("guest_memfd mmap");

	kvm->ram_guest_memfd = ret;
	kvm->ram_pagesize = getpagesize();

	return addr;
}
