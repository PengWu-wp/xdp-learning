/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <linux/err.h>

#include "params.h"
#include "logging.h"
#include "util.h"

#define PROG_NAME "xdp_prog_user"

//static const char *map_name = "blacklist_map";
#define MAP_PATH "/sys/fs/bpf/blacklist_map"
const char *map_path = MAP_PATH;
static const char *file_name[1] = {"xdp_prog_kern.o"};

static const struct loadopt {
	bool help;
	struct iface iface;
	struct multistring filenames;
	const char *pin_path;
	char *section_name;
	char *prog_name;
	enum xdp_attach_mode mode;
} defaults_load = {
		.mode = XDP_MODE_NATIVE,
		.filenames = {file_name, 1},
		.pin_path = MAP_PATH
};

struct enum_val xdp_modes[] = {
		{"native", XDP_MODE_NATIVE},
		{"skb", XDP_MODE_SKB},
		{"hw", XDP_MODE_HW},
		{"unspecified", XDP_MODE_UNSPEC},
		{NULL, 0}
};


static struct prog_option load_options[] = {
		DEFINE_OPTION("mode", OPT_ENUM, struct loadopt, mode,
		.short_opt = 'm',
		.typearg = xdp_modes,
		.metavar = "<mode>",
		.help = "Load XDP program in <mode>; default native"),
		DEFINE_OPTION("pin-path", OPT_STRING, struct loadopt, pin_path,
		.short_opt = 'p',
		.help = "Path to pin maps under (must be in bpffs)."),
		DEFINE_OPTION("section", OPT_STRING, struct loadopt, section_name,
		.metavar = "<section>",
		.short_opt = 's',
		.help = "ELF section name of program to load (default: first in file)."),
		DEFINE_OPTION("prog-name", OPT_STRING, struct loadopt, prog_name,
		.metavar = "<prog_name>",
		.short_opt = 'n',
		.help = "BPF program name of program to load (default: first in file)."),
		DEFINE_OPTION("dev", OPT_IFNAME, struct loadopt, iface,
		.positional = true,
		.metavar = "<ifname>",
		.required = true,
		.help = "Load on device <ifname>"),
		DEFINE_OPTION("filenames", OPT_MULTISTRING, struct loadopt, filenames,
		.metavar = "<filenames>",
		.short_opt = 'f',
		.help = "Load programs from <filenames>"),
		END_OPTIONS
};

int do_load(const void *cfg, __unused const char *pin_root_path)
{
	const struct loadopt *opt = cfg;
	struct xdp_program **progs, *p;
	char errmsg[STRERR_BUFSIZE];
	int err = EXIT_SUCCESS;
	size_t num_progs, i;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			.pin_root_path = opt->pin_path);

	if (opt->section_name && opt->prog_name) {
		pr_warn("Only one of --section or --prog-name can be set\n");
		return EXIT_FAILURE;
	}

	num_progs = opt->filenames.num_strings;
	if (!num_progs) {
		pr_warn("Need at least one filename to load\n");
		return EXIT_FAILURE;
	} else if (num_progs > 1 && opt->mode == XDP_MODE_HW) {
		pr_warn("Cannot attach multiple programs in HW mode\n");
		return EXIT_FAILURE;
	}

	progs = calloc(num_progs, sizeof(*progs));
	if (!progs) {
		pr_warn("Couldn't allocate memory\n");
		return EXIT_FAILURE;
	}

	pr_debug("Loading %zu files on interface '%s'.\n",
			 num_progs, opt->iface.ifname);

	/* libbpf spits out a lot of unhelpful error messages while loading.
	 * Silence the logging so we can provide our own messages instead; this
	 * is a noop if verbose logging is enabled.
	 */
	silence_libbpf_logging();

	retry:
	for (i = 0; i < num_progs; i++) {
		DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

		p = progs[i];
		if (p)
			xdp_program__close(p);

		if (opt->prog_name) {
			xdp_opts.open_filename = opt->filenames.strings[i];
			xdp_opts.prog_name = opt->prog_name;
			xdp_opts.opts = &opts;

			p = xdp_program__create(&xdp_opts);
		} else {
			p = xdp_program__open_file(opt->filenames.strings[i],
									   opt->section_name, &opts);
		}

		err = libxdp_get_error(p);
		if (err) {
			if (err == -EPERM && !double_rlimit())
				goto retry;

			libxdp_strerror(err, errmsg, sizeof(errmsg));
			pr_warn("Couldn't open file '%s': %s\n",
					opt->filenames.strings[i], errmsg);
			goto out;
		}

		xdp_program__print_chain_call_actions(p, errmsg, sizeof(errmsg));
		pr_debug("XDP program %zu: Run prio: %d. Chain call actions: %s\n",
				 i, xdp_program__run_prio(p), errmsg);

		/* This will set pin_path for all maps in obj, xdp-tools will later pin them */
		if (opt->pin_path) {
			struct bpf_map *map;

			bpf_object__for_each_map(map, xdp_program__bpf_obj(p)) {
				err = bpf_map__set_pin_path(map, opt->pin_path);
				if (err) {
					pr_warn("Error clearing map pin path: %s\n",
							strerror(-err));
					goto out;
				}
			}
		}

		progs[i] = p;
	}

	err = xdp_program__attach_multi(progs, num_progs,
									opt->iface.ifindex, opt->mode, 0);
	if (err) {
		if (err == -EPERM && !double_rlimit())
			goto retry;

		if (err == -EOPNOTSUPP &&
			(opt->mode == XDP_MODE_NATIVE || opt->mode == XDP_MODE_HW)) {
			pr_warn("Attaching XDP program in %s mode not supported - try %s mode.\n",
					opt->mode == XDP_MODE_NATIVE ? "native" : "HW",
					opt->mode == XDP_MODE_NATIVE ? "SKB" : "native or SKB");
		} else {
			libbpf_strerror(err, errmsg, sizeof(errmsg));
			pr_warn("Couldn't attach XDP program on iface '%s': %s(%d)\n",
					opt->iface.ifname, errmsg, err);
		}
		goto out;
	}
	printf("Success: XDP program attached on iface '%s'\n", opt->iface.ifname);

	out:
	for (i = 0; i < num_progs; i++)
		if (progs[i])
			xdp_program__close(progs[i]);
	free(progs);
	return err;
}

static const struct unloadopt {
	bool all;
	__u32 prog_id;
	struct iface iface;
} defaults_unload = {};

static struct prog_option unload_options[] = {
		DEFINE_OPTION("dev", OPT_IFNAME, struct unloadopt, iface,
		.positional = true,
		.metavar = "<ifname>",
		.help = "Unload from device <ifname>"),
		DEFINE_OPTION("id", OPT_U32, struct unloadopt, prog_id,
		.metavar = "<id>",
		.short_opt = 'i',
		.help = "Unload program with id <id>"),
		DEFINE_OPTION("all", OPT_BOOL, struct unloadopt, all,
		.short_opt = 'a',
		.help = "Unload all programs from interface"),
		END_OPTIONS
};

int do_unload(const void *cfg, __unused const char *pin_root_path)
{
	const struct unloadopt *opt = cfg;
	struct xdp_multiprog *mp = NULL;
	enum xdp_attach_mode mode;
	int err = EXIT_FAILURE;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			.pin_root_path = pin_root_path);

	if (!opt->all && !opt->prog_id) {
		pr_warn("Need prog ID or --all\n");
		goto out;
	}

	if (!opt->iface.ifindex) {
		pr_warn("Must specify ifname\n");
		goto out;
	}

	mp = xdp_multiprog__get_from_ifindex(opt->iface.ifindex);
	if (IS_ERR_OR_NULL(mp)) {
		pr_warn("No XDP program loaded on %s\n", opt->iface.ifname);
		mp = NULL;
		goto out;
	}

	if (opt->all) {
		err = xdp_multiprog__detach(mp);
		if (err) {
			pr_warn("Unable to detach XDP program: %s\n",
					strerror(-err));
			goto out;
		}
	} else {
		struct xdp_program *prog = NULL;

		while ((prog = xdp_multiprog__next_prog(prog, mp))) {
			if (xdp_program__id(prog) == opt->prog_id) {
				mode = xdp_multiprog__attach_mode(mp);
				goto found;
			}
		}

		if (xdp_multiprog__is_legacy(mp)) {
			prog = xdp_multiprog__main_prog(mp);
			if (xdp_program__id(prog) == opt->prog_id) {
				mode = xdp_multiprog__attach_mode(mp);
				goto found;
			}
		}

		prog = xdp_multiprog__hw_prog(mp);
		if (xdp_program__id(prog) == opt->prog_id) {
			mode = XDP_MODE_HW;
			goto found;
		}

		pr_warn("Program with ID %u not loaded on %s\n",
				opt->prog_id, opt->iface.ifname);
		err = -ENOENT;
		goto out;

		found:
		pr_debug("Detaching XDP program with ID %u from %s\n",
				 xdp_program__id(prog), opt->iface.ifname);
		err = xdp_program__detach(prog, opt->iface.ifindex, mode, 0);
		if (err) {
			pr_warn("Unable to detach XDP program: %s\n",
					strerror(-err));
			goto out;
		}
	}
	printf("Success: XDP program detached from iface '%s'\n", opt->iface.ifname);

	out:
	xdp_multiprog__close(mp);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

static const struct statusopt {
	struct iface iface;
} defaults_status = {};

static struct prog_option status_options[] = {
		DEFINE_OPTION("dev", OPT_IFNAME, struct statusopt, iface,
		.positional = true, .metavar = "[ifname]",
		.help = "Show status for device [ifname] (default all interfaces)"),
		END_OPTIONS
};

int do_status(const void *cfg, __unused const char *pin_root_path)
{
	const struct statusopt *opt = cfg;

	printf("CURRENT XDP PROGRAM STATUS:\n\n");
	return iface_print_status(opt->iface.ifindex ? &opt->iface : NULL);
}

static const struct cleanopt {
	struct iface iface;
} defaults_clean = {};

static struct prog_option clean_options[] = {
		DEFINE_OPTION("dev", OPT_IFNAME, struct cleanopt, iface,
		.positional = true, .metavar = "[ifname]",
		.help = "Clean up detached program links for [ifname] (default all interfaces)"),
		END_OPTIONS
};

int do_clean(const void *cfg, __unused const char *pin_root_path)
{
	const struct cleanopt *opt = cfg;

	printf("Cleaning up detached XDP program links for %s\n", opt->iface.ifindex ?
															  opt->iface.ifname : "all interfaces");
	/* Remove pinned map */
	int err = remove(map_path);
	if (err) {
		fprintf(stderr, "Error: pinned map remove failed: %s\n",
				strerror(-err));
		return EXIT_FAILURE;
	} else {
		printf("Pinned map removed\n");
		return 0;
	}

	return libxdp_clean_references(opt->iface.ifindex);
}


static const struct mapopt {
	char *key;
	bool delete;
	bool all;
	bool dump;
} defaults_map = {
		.dump = false,
		.all = false,
		.delete = false
};

static struct prog_option map_options[] = {
		DEFINE_OPTION("key", OPT_STRING, struct mapopt, key,
		.metavar = "[key]",
		.short_opt = 'K',
		.help = "Update IP in black_list"),
		DEFINE_OPTION("all", OPT_BOOL, struct mapopt, all,
		.short_opt = 'a',
		.help = "Delete all entries in map"),
		DEFINE_OPTION("dump", OPT_BOOL, struct mapopt, dump,
		.short_opt = 'd',
		.help = "Display all entries in map"),
		DEFINE_OPTION("delete", OPT_BOOL, struct mapopt, delete,
		.short_opt = 'D',
		.help = "Performing deletion, use -a / --all to delete all"),
		END_OPTIONS
};

int do_map(const void *cfg, __unused const char *pin_root_path) {
	const struct mapopt *opt = cfg;
	int err;

	__u32 key;
	__u32 value = 1;
	__u32 next_key, lookup_key = -1;


	int map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "Error: Failed to fetch the map: %d (%s)\n",
				map_fd, strerror(errno));
		return EXIT_FAILURE;
	}

	if (opt->dump) {
		printf("black_list_ipaddr:\n");
		while (bpf_map_get_next_key(map_fd, &lookup_key, &next_key) == 0) {
			struct in_addr ia = {next_key};
			printf("%s\n", inet_ntoa(ia));
			lookup_key = next_key;
		}
		return 0;
	}

	if (!opt->delete) {
		if (!opt->key) {
			pr_warn("Key not specified, use -K/--key\n");
			return EXIT_FAILURE;
		}
		key = inet_addr(opt->key);
		err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
		if (err) {
			fprintf(stderr, "Error: Failed to update map: %d (%s)\n",
					map_fd, strerror(errno));
			return EXIT_FAILURE;
		}
		printf("Success: map updated\n");

	} else {
		if (opt->all) {

			while (bpf_map_get_next_key(map_fd, &lookup_key, &next_key) == 0) {
				err = bpf_map_delete_elem(map_fd, &next_key);
				if (err) {
					fprintf(stderr, "Error: Failed to delete map: %d (%s)\n",
							map_fd, strerror(errno));
					return EXIT_FAILURE;
				}
				lookup_key = next_key;
			}
			printf("Success: All entries deleted in map!\n");
		} else {
			if (!opt->key) {
				pr_warn("Key not specified, use -K/--key\n");
				return EXIT_FAILURE;
			}
			key = inet_addr(opt->key);
			value = 0;
			err = bpf_map_lookup_elem(map_fd, &key, &value);
			if (err) {
				fprintf(stderr, "Error: bpf_map_lookup_elem failed: %d (%s)\n",
						map_fd, strerror(errno));
				return EXIT_FAILURE;
			}
			if (!value) {
				printf("'%s' not exists in map\n",opt->key);
				return 0;
			}
			err = bpf_map_delete_elem(map_fd, &key);
			if (err) {
				fprintf(stderr, "Error: Failed to delete map: %d (%s)\n",
						map_fd, strerror(errno));
				return EXIT_FAILURE;
			}
			printf("Success: '%s' deleted in map\n", opt->key);
		}
	}
	return 0;
}


int do_help(__unused const void *cfg, __unused const char *pin_root_path) {
	fprintf(stderr,
			"Usage: xdp-loader COMMAND [options]\n"
			"\n"
			"COMMAND can be one of:\n"
			"       load        - load an XDP program on an interface\n"
			"       unload      - unload an XDP program from an interface\n"
			"       map         - perform map updates and key deletions\n"
			"       status      - show current XDP program status\n"
			"       clean       - clean up detached program links in XDP bpffs directory\n"
			"       help        - show this help message\n"
			"\n"
			"Use 'xdp-loader COMMAND --help' to see options for each command\n");
	return -1;
}


static const struct prog_command cmds[] = {
		DEFINE_COMMAND(load, "Load an XDP program on an interface"),
		DEFINE_COMMAND(unload, "Unload an XDP program from an interface"),
		DEFINE_COMMAND(clean, "Clean up detached program links in XDP bpffs directory"),
		DEFINE_COMMAND(status, "Show XDP program status"),
		DEFINE_COMMAND(map, "Update eBPF map"),
		{ .name = "help", .func = do_help, .no_cfg = true },
		END_COMMANDS
};

union all_opts {
	struct loadopt load;
	struct unloadopt unload;
	struct statusopt status;
	struct mapopt map;
};

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
								 sizeof(union all_opts), PROG_NAME, false);

	return do_help(NULL, NULL);
}
