#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>

struct mem_info {
	uint64_t mem_total;
	uint64_t mem_free;
	uint64_t mem_avail;
	uint64_t shmem;
	uint64_t buffers;
	uint64_t cache;
	uint64_t swap_total;
	uint64_t swap_free;
	uint64_t comm_total;
	uint64_t comm_used;
	uint64_t comm_free;
	uint64_t low_total;
	uint64_t low_used;
	uint64_t low_free;
	uint64_t hi_total;
	uint64_t hi_used;
	uint64_t hi_free;
};

static const char size_suffix[7] = { 'B', 'K', 'M', 'G', 'T', 'P', '\0' };

#define PRETTY_MAX_SIZE    (40)
#define ARRAY_SZ(x)        (sizeof(x) / sizeof(*x))

#define PRETTY_EXPO_B    (1)
#define PRETTY_EXPO_K    (2)
#define PRETTY_EXPO_M    (3)
#define PRETTY_EXPO_G    (4)
#define PRETTY_EXPO_T    (5)
#define PRETTY_EXPO_P    (6)

#if defined (__GNUC__) || defined (__clang__)
# undef NORETURN
# define NORETURN    __attribute__((noreturn))
#else
/* We don't need it. */
# undef NORETURN
# define NORETURN
#endif

static uint64_t conv_to_u64(const char *s)
{
	uint64_t value;
	char *eptr;

	value = strtoull(s, &eptr, 10);
	if (errno != 0)
		err(EXIT_FAILURE, "strtoull()");

	if (eptr == s)
		errx(EXIT_FAILURE, "no digits are available in: '%s'.", s);

	return (value);
}

static inline double power(int base, int expo)
{
        double mul2;

	if (expo == 0)
		return (1.0);

	mul2 = 1.0;
	while (expo--)
		mul2 *= (double)base;
        return (mul2);
}

static char *pretty_size(uint64_t size, int expo, int is_si, int do_pretty)
{
        uint64_t bytes;
	char *p;
	int base, i, format_size;

	base = is_si ? 1000 : 1024;
	/* Convert from kB to bytes. */
	bytes = size * (uint64_t)1024;

	p = calloc(PRETTY_MAX_SIZE, sizeof(char));
	if (p == NULL)
		err(EXIT_FAILURE, "calloc()");

	if (do_pretty) {
		for (i = 0; ARRAY_SZ(size_suffix); i++) {
			if (is_si) {
				format_size = snprintf(
					p, PRETTY_MAX_SIZE, "%.1f%c",
					(float)(bytes / power(base, i)),
					size_suffix[i]);
				if (format_size <= 4)
					return (p);

				format_size = snprintf(
					p, PRETTY_MAX_SIZE, "%ld%c",
					(long)(bytes / power(base, i)),
					size_suffix[i]);
				if (format_size <= 4)
					return (p);
			} else {
				format_size = snprintf(
					p, PRETTY_MAX_SIZE, "%.1f%ci",
					(float)(bytes / power(base, i)),
					size_suffix[i]);
				if (format_size <= 5) /* Size and the "i" suffix. */
					return (p);

			        format_size = snprintf(
					p, PRETTY_MAX_SIZE, "%ld%ci",
					(long)(bytes / power(base, i)),
					size_suffix[i]);
				if (format_size <= 5)
					return (p);
			}
		}
	} else {
		switch (expo) {
		case 0:
			snprintf(p, PRETTY_MAX_SIZE, "%ld",
				 (uint64_t)(bytes / base));
		        break;
		case 1:
			snprintf(p, PRETTY_MAX_SIZE, "%ld", bytes);
		        break;
		default:
			snprintf(p, PRETTY_MAX_SIZE, "%ld",
				 (uint64_t)(bytes / power(base, expo - 1)));
		        break;
		}

	        return (p);
	}
}

static char *read_meminfo_file(void)
{
	int fd;
	char buf[200];
	char *p;
	size_t extra_bytes, prev_bytes, total_bytes;
	ssize_t read_bytes;

	fd = open("/proc/meminfo", O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			errx(EXIT_FAILURE, "cannot find /proc/meminfo. Is /proc mounted?");
		err(EXIT_FAILURE, "open()");
	}

	p = calloc(1, sizeof(char));
	if (p == NULL)
		err(EXIT_FAILURE, "calloc()");

	memset(buf, '\0', sizeof(buf));
	extra_bytes = prev_bytes = total_bytes = 0;
	while ((read_bytes = read(fd, buf, sizeof(buf) - 1)) > 0) {
		if (extra_bytes <= sizeof(buf)) {
			/* Subtract the unneeded bytes,
			   that we do not need to allocate. */
			if (prev_bytes > total_bytes)
				prev_bytes -= prev_bytes - total_bytes;
		        extra_bytes = sizeof(buf) * 4;
			prev_bytes += extra_bytes;
			p = realloc(p, prev_bytes);
			if (p == NULL)
				err(EXIT_FAILURE, "realloc()");
		} else {
			extra_bytes -= sizeof(buf);
	        }

		memcpy(p + total_bytes, buf, sizeof(buf));
	        memset(buf, '\0', sizeof(buf));
	        /* Add total how much we have read so far. */
		total_bytes += (size_t)read_bytes;
        }
	close(fd);
	return (p);
}

static uint64_t get_mem_kv(const char *mbuf, const char *key)
{
	char *spos, *p;
	size_t pos;
	uint64_t val;

	p = strdup(mbuf);
	if (p == NULL)
		err(EXIT_FAILURE, "strdup()");

	spos = strstr(p, key);
	if (spos == NULL) {
		free(p);
		return ((uint64_t)0);
	}

	/* Equavalent of strcspn().
	   See: https://codebrowser.dev/glibc/glibc/string/strcspn.c.html#
	   Subtract the initial position spos, from the new position
	   we got from strchr(). */
        pos = (size_t)(strchr(spos, '\n') - spos);
	spos[pos] = '\0';
        while (*spos != ' ')
		spos++;
	while (*spos == ' ')
		spos++;
	pos = strcspn(spos, " ");
	spos[pos] = '\0';

	val = conv_to_u64(spos);
	free(p);
        return (val);
}

static void do_collect_meminfo(struct mem_info *mi, const char *mbuf,
			       int add_mem, int add_swap, int add_comm,
			       int add_lohi)
{
	if (add_mem) {
		mi->mem_total = get_mem_kv(mbuf, "MemTotal:");
		mi->mem_free = get_mem_kv(mbuf, "MemFree:");
		mi->mem_avail = get_mem_kv(mbuf, "MemAvailable:");
		mi->shmem = get_mem_kv(mbuf, "Shmem:");
		mi->buffers = get_mem_kv(mbuf, "Buffers:");
		mi->cache = get_mem_kv(mbuf, "Cached:");
	}

	if (add_swap) {
		mi->swap_total = get_mem_kv(mbuf, "SwapTotal:");
		mi->swap_free = get_mem_kv(mbuf, "SwapFree:");
	}

	if (add_comm) {
		mi->comm_total = get_mem_kv(mbuf, "CommitLimit:");
		mi->comm_used = get_mem_kv(mbuf, "Committed_AS:");
	        mi->comm_free = (mi->comm_total > mi->comm_used) ?
			mi->comm_total - mi->comm_used :
			(uint64_t)0;
	}

	if (add_lohi) {
		mi->low_total = get_mem_kv(mbuf, "LowTotal:");
		if (mi->low_total == (uint64_t)0)
			mi->low_total = mi->mem_total;

		mi->low_free = get_mem_kv(mbuf, "LowFree:");
		if (mi->low_free == (uint64_t)0)
			mi->low_free = mi->mem_free;

		mi->low_used = mi->low_total - mi->low_free;

		mi->hi_total = get_mem_kv(mbuf, "HighTotal:");
		if (mi->hi_total == (uint64_t)0)
			mi->hi_total = (uint64_t)0;

		mi->hi_free = get_mem_kv(mbuf, "HighFree:");
		if (mi->hi_free == (uint64_t)0)
			mi->hi_free = 0;
		
		mi->hi_used = mi->hi_total - mi->hi_free;
	}
}

/* Wrapper around pretty_size(). */
#define WRAP_PRETTY_SIZE(mem_size, default_unit, is_si, is_pretty, format) \
	do {								\
		nice_size = pretty_size(mem_size, default_unit, is_si, is_pretty); \
		format;							\
		free(nice_size);					\
	} while (0)							\

static void print_collected_info(struct mem_info *mi, int buff_cache,
				 int default_unit, int is_si, int print_mem,
				 int print_swap, int print_comm, int print_lohi,
				 int is_pretty, int is_total)
{
	char *nice_size;	
	uint64_t total_have, used_space, free_space;

	/* Include (the sum of buffers and cache), if buff_cache is enabled. */
	if (buff_cache)
		fprintf(stdout,
			"               total        used        free      shared  buff/cache   available");
	else
		fprintf(stdout,
			"               total        used        free      shared     buffers       cache   available");

	if (print_mem) {
		/* Print the output like:
		   Mem:           a       b       c       d       e       f
		   And for swap, just do the same, except that the last three
		   elements will not be present. */
		fputs("\nMem: ", stdout);

		WRAP_PRETTY_SIZE(mi->mem_total, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%15s", nice_size));
		WRAP_PRETTY_SIZE(mi->mem_total - mi->mem_avail, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
		WRAP_PRETTY_SIZE(mi->mem_free, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
		WRAP_PRETTY_SIZE(mi->shmem, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));

		if (buff_cache) {
			WRAP_PRETTY_SIZE(mi->buffers + mi->cache, default_unit, is_si, is_pretty,
					 fprintf(stdout, "%12s", nice_size));
		} else {
			WRAP_PRETTY_SIZE(mi->buffers, default_unit, is_si, is_pretty,
					 fprintf(stdout, "%12s", nice_size));
			WRAP_PRETTY_SIZE(mi->cache, default_unit, is_si, is_pretty,
					 fprintf(stdout, "%12s", nice_size));
		}

		/* Available. */
		WRAP_PRETTY_SIZE(mi->mem_avail, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
	}

	if (print_lohi) {
		/* According to man 5 proc, there should be Low* and High* key values
		   in the /proc/meminfo pseudo-file. However, only, if the kernel was
		   configured with CONFIG_HIGHMEM=1. Otherwise, it's empty. free(1)
		   reports MemTotal as LowTotal, even if CONFIG_HIGHMEM isn't enabled.

		   As we'll search, if we don't have the key called High*, we'll just
		   High values to zero. */
		fputs("\nLow: ", stdout);
		WRAP_PRETTY_SIZE(mi->low_total, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%15s", nice_size));
		WRAP_PRETTY_SIZE(mi->low_used, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
		
		WRAP_PRETTY_SIZE(mi->low_free, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
		fputs("\nHigh: ", stdout);
		WRAP_PRETTY_SIZE(mi->hi_total, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%14s", nice_size));
		WRAP_PRETTY_SIZE(mi->hi_used, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
		WRAP_PRETTY_SIZE(mi->hi_free, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
	}

	/* Print swap information, when print_swap is not equal to 0. */
	if (print_swap) {
		fputs("\nSwap: ", stdout);
		WRAP_PRETTY_SIZE(mi->swap_total, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%14s", nice_size));
		WRAP_PRETTY_SIZE(mi->swap_total - mi->swap_free, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
		WRAP_PRETTY_SIZE(mi->swap_free, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
	}
	if (print_comm) {
		fputs("\nComm: ", stdout);
		WRAP_PRETTY_SIZE(mi->comm_total, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%14s", nice_size));
		WRAP_PRETTY_SIZE(mi->comm_used, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
		WRAP_PRETTY_SIZE(mi->comm_free, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
	}

	total_have = used_space = free_space = (uint64_t)0;
	if (is_total) {
		fputs("\nTotal: ", stdout);
		/* Add memory. */
		if (print_mem) {
			total_have = mi->mem_total;
			used_space = mi->mem_total - mi->mem_avail;
			free_space = mi->mem_free;
		}

		/* Add swap. */
		if (print_swap) {
			total_have += mi->swap_total;
			used_space += mi->swap_total - mi->swap_free;
			free_space += mi->swap_free;
		}

		/* Add comm. */
		if (print_comm) {
			total_have += mi->comm_total;
			used_space += mi->comm_used;
			free_space += mi->comm_free;
		}

		/* Add Lohi. */
		if (print_lohi) {
			total_have += mi->low_total;
			used_space += mi->low_used;
			free_space += mi->low_free;
		}

		WRAP_PRETTY_SIZE(total_have, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%13s", nice_size));
		WRAP_PRETTY_SIZE(used_space, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
		WRAP_PRETTY_SIZE(free_space, default_unit, is_si, is_pretty,
				 fprintf(stdout, "%12s", nice_size));
	}
	fputc('\n', stdout);
}

NORETURN
static void print_usage(int status)
{
	FILE *out;

	out = (status == EXIT_SUCCESS) ? stdout : stderr;
	fputs("Usage:\n"
	      " free [options]\n\n"
	      "Options:\n"
	      " -b, --bytes\t\tDisplay output in bytes\n"
	      "     --kilo\t\tDisplay output in kilobytes\n"
	      "     --mega\t\tdisplay output in megabytes\n"
	      "     --giga\t\tDisplay output in gigabytes\n"
	      "     --tera\t\tDisplay output in terabytes\n"
	      "     --peta\t\tDisplay output in petabytes\n"
	      " -k, --kibi\t\tDisplay output in kibibytes\n"
	      " -m, --mebi\t\tDisplay output in mebibytes\n"
	      " -g, --gibi\t\tDisplay output in gibibytes\n"
	      "     --tebi\t\tDisplay output in tebibytes\n"
	      "     --pebi\t\tDisplay output in pebibytes\n"
	      " -h, --human\t\tDisplay output in human-readable format\n"
	      "     --pretty\t\tAlias of '--human'\n"
	      "     --si\t\tDivide the size by 1000 instead of 1024\n"
	      " -l, --lohi\t\tDisplay LOW and HIGH memory usage\n"
	      " -t, --total\t\tDisplay the total of 'max', 'used', and 'free'\n"
	      " -v, --committed\tDisplay the committed memory\n"
	      " -s, --seconds\t\tDisplay memory usage continuously with a delay\n"
	      " -c, --count\t\tDisplay the memory usage n-number of times\n"
	      " -w, --wide\t\tExpand 'buff/cache' to 'buffers' and 'cache'\n"
	      "     --noswap\t\tDo not display the swap space usage\n"
	      "     --nomem\t\tDo not display the acquired-memory usage\n"
	      "     --help\t\tDisplay this help menu\n", out);
	exit(status);
}

int main(int argc, char **argv)
{
	char *mbuf;
        struct mem_info mi;
	int c, expo_is, is_si, is_comm, is_lohi,
		is_total, is_pretty, is_wide, is_swap, is_mem;
	uint64_t seconds_after, howmany_times;
	struct timespec ts;
	const char *short_opts;

        static struct option lopts[] = {
		{ "help",      no_argument,       0, 1   },
		{ "bytes",     no_argument,       0, 'b' },
		{ "kilo",      no_argument,       0, 2   },
		{ "mega",      no_argument,       0, 3   },
		{ "giga",      no_argument,       0, 4   },
		{ "tera",      no_argument,       0, 5   },
		{ "peta",      no_argument,       0, 6   },
		{ "mebi",      no_argument,       0, 'm' },
		{ "kibi",      no_argument,       0, 'k' },
		{ "gibi",      no_argument,       0, 'g' },
		{ "tebi",      no_argument,       0, 7   },
		{ "pebi",      no_argument,       0, 8   },
		{ "human",     no_argument,       0, 'h' },
		{ "pretty",    no_argument,       0, 9   },
		{ "si",        no_argument,       0, 10  },
		{ "lohi",      no_argument,       0, 'l' },
		{ "total",     no_argument,       0, 't' },
		{ "committed", no_argument,       0, 'v' },
	        { "seconds",   required_argument, 0, 's' },
		{ "count",     required_argument, 0, 'c' },
		{ "wide",      no_argument,       0, 'w' },
		{ "noswap",    no_argument,       0, 11  },
		{ "nomem",     no_argument,       0, 12  },
		{ NULL,        0,                 0, 0   },
	};

	short_opts = "bkmghltvs:c:w";
	seconds_after = howmany_times = (uint64_t)0;
        expo_is = PRETTY_EXPO_K;
	is_si = is_comm = is_lohi = is_total = is_pretty = 0;
	is_wide = is_swap = is_mem = 1;

	while ((c = getopt_long(argc, argv, short_opts, lopts, NULL)) != -1) {
		switch (c) {
		case 1:
			/* flag: --help */
			print_usage(EXIT_SUCCESS);
		case 2:
			/* flag: --kilo */
			expo_is = PRETTY_EXPO_K;
			is_si = 1;
		        break;
		case 3:
			/* flag: --mega */
			expo_is = PRETTY_EXPO_M;
			is_si = 1;
			break;
		case 4:
			/* flag: --giga */
			expo_is = PRETTY_EXPO_G;
			is_si = 1;
			break;
		case 5:
			/* flag: --tera */
			expo_is = PRETTY_EXPO_T;
			is_si = 1;
			break;
		case 6:
			/* flag: --peta */
			expo_is = PRETTY_EXPO_P;
			is_si = 1;
			break;
		case 'b':
			/* flag: --bytes */
		        expo_is = PRETTY_EXPO_B;
		        break;
		case 'k':
			/* flag: --kibi */
			expo_is = PRETTY_EXPO_K;
			break;
		case 'm':
			/* flag: --mibi */
			expo_is = PRETTY_EXPO_M;
			break;
		case 'g':
			/* flag: --gibi */
			expo_is = PRETTY_EXPO_G;
			break;
		case 7:
			/* flag: --tibi */
		        expo_is = PRETTY_EXPO_T;
			break;
		case 8:
			/* flag: --pibi */
		        expo_is = PRETTY_EXPO_P;
			break;
		case 'h':
		case 9:
		        is_pretty = 1;
			break;
		case 10:
			is_si = 1;
			break;
		case 'l':
			is_lohi = 1;
			break;
		case 't':
		        is_total = 1;
			break;
		case 'v':
			is_comm = 1;
			break;
		case 's':
			/* As we're already requiring argument for conv_to_u64(),
			   we don't have to check whether there's anything or not. */
			seconds_after = conv_to_u64(optarg);
		        for (;;) {
				mbuf = read_meminfo_file();
				do_collect_meminfo(&mi, mbuf, is_mem, is_swap, is_comm, is_lohi);
				print_collected_info(
					&mi, is_wide, expo_is, is_si, is_mem,
				        is_swap, is_comm, is_lohi, is_pretty, is_total);
			        fputc('\n', stdout);
				free(mbuf);
				ts.tv_nsec = 0;
				ts.tv_sec = (time_t)seconds_after;
				if (nanosleep(&ts, NULL) == -1)
					err(EXIT_FAILURE, "nanosleep()");
			}
			break;
		case 'c':
			howmany_times = conv_to_u64(optarg);
			while (howmany_times--) {
				mbuf = read_meminfo_file();
				do_collect_meminfo(&mi, mbuf, is_mem, is_swap, is_comm, is_lohi);
				/*
				  static void print_collected_info(struct mem_info *mi, int buff_cache,
				  int default_unit, int is_si, int print_mem,
				  int print_swap, int print_comm, int print_lohi,
				  int is_pretty, int is_total)
				*/
				print_collected_info(
					&mi, is_wide, expo_is, is_si, is_mem,
				        is_swap, is_comm, is_lohi, is_pretty, is_total);
			        fputc('\n', stdout);
				free(mbuf);
				ts.tv_sec = (time_t)1;
				ts.tv_nsec = 0;
			        if (nanosleep(&ts, NULL) == -1)
					err(EXIT_FAILURE, "nanosleep()");
		        }
			exit(EXIT_SUCCESS);
		case 'w':
			is_wide = 0;
		        break;
		case 11:
			is_swap = 0;
		        break;
		case 12:
			is_mem = 0;
			break;
		case '?':
			exit(EXIT_FAILURE);
		default:
			exit(EXIT_FAILURE);
		}
	}

	mbuf = read_meminfo_file();
	do_collect_meminfo(&mi, mbuf, is_mem, is_swap, is_comm, is_lohi);
	if (is_mem == 0 && is_swap == 0)
		errx(EXIT_FAILURE,
		     "You cannot disable both :)");
        print_collected_info(&mi, is_wide, expo_is, is_si, is_mem,
			     is_swap, is_comm, is_lohi, is_pretty, is_total);

	free(mbuf);
}
