const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    b.reference_trace = 64;

    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const skip_crun_build = b.option(bool, "skip_crun_build", "Skip crun build") orelse false;

    const zstd = b.createModule(.{});
    zstd.addAssemblyFile(b.path("zstd/lib/decompress/huf_decompress_amd64.S"));
    zstd.addCSourceFiles(.{
        .files = &[_][]const u8{
            "zstd/lib/common/debug.c",
            "zstd/lib/common/entropy_common.c",
            "zstd/lib/common/error_private.c",
            "zstd/lib/common/fse_decompress.c",
            "zstd/lib/common/pool.c",
            "zstd/lib/common/threading.c",
            "zstd/lib/common/xxhash.c",
            "zstd/lib/common/zstd_common.c",

            "zstd/lib/compress/fse_compress.c",
            "zstd/lib/compress/hist.c",
            "zstd/lib/compress/huf_compress.c",
            "zstd/lib/compress/zstd_compress.c",
            "zstd/lib/compress/zstd_compress_literals.c",
            "zstd/lib/compress/zstd_compress_sequences.c",
            "zstd/lib/compress/zstd_compress_superblock.c",
            "zstd/lib/compress/zstd_double_fast.c",
            "zstd/lib/compress/zstd_fast.c",
            "zstd/lib/compress/zstd_lazy.c",
            "zstd/lib/compress/zstd_ldm.c",
            "zstd/lib/compress/zstdmt_compress.c",
            "zstd/lib/compress/zstd_opt.c",

            "zstd/lib/decompress/huf_decompress.c",
            "zstd/lib/decompress/zstd_ddict.c",
            "zstd/lib/decompress/zstd_decompress_block.c",
            "zstd/lib/decompress/zstd_decompress.c",
        },
    });

    const fuse_fss = b.createModule(.{});
    fuse_fss.addIncludePath(b.path("zstd/lib"));

    fuse_fss.addIncludePath(b.path("libfuse/include"));
    fuse_fss.addIncludePath(b.path("libfuse/build"));

    fuse_fss.addCSourceFiles(.{
        .files = &[_][]const u8{
            "libfuse/lib/fuse_opt.c",
            "libfuse/lib/helper.c",
            "libfuse/lib/fuse_log.c",
            "libfuse/lib/fuse_lowlevel.c",
            "libfuse/lib/mount_util.c",
            "libfuse/lib/fuse.c",
            "libfuse/lib/fuse_signals.c",
            "libfuse/lib/fuse_loop_mt.c",
            "libfuse/lib/buffer.c",
            "libfuse/lib/mount.c",
            "libfuse/lib/fuse_loop.c",
            "libfuse/lib/modules/subdir.c",
            "libfuse/lib/modules/iconv.c",
            "libfuse/lib/cuse_lowlevel.c",
        },
        .flags = &[_][]const u8{
            // TODO: figure out where to get this value from
            "-DFUSE_USE_VERSION=317",
            // TODO: make sure this is correct value as well, or maybe we're supposed to dynamically link
            "-DFUSERMOUNT_DIR=\"/usr/local/bin\"",
        },
    });

    fuse_fss.addIncludePath(b.path("fuse-overlayfs"));
    fuse_fss.addIncludePath(b.path("fuse-overlayfs/lib"));
    fuse_fss.addCSourceFiles(.{
        .files = &[_][]const u8{
            "fuse-overlayfs/main.c",
            "fuse-overlayfs/lib/hash.c",
            "fuse-overlayfs/lib/bitrotate.c",
            "fuse-overlayfs/utils.c",
            "fuse-overlayfs/plugin-manager.c",
            "fuse-overlayfs/direct.c",
        },
        .flags = &[_][]const u8{
            "-Dmain=overlayfs_main",
            // collision with libcrun
            "-Dsafe_openat=overlayfs_safe_openat",
            "-DPKGLIBEXECDIR=\"\"",
            "-Wno-format",
            "-Wno-switch",
        },
    });
    fuse_fss.addCSourceFiles(.{
        .files = &[_][]const u8{
            "squashfuse/ll_main.c",
            "squashfuse/ll.c",
            "squashfuse/ll_inode.c",
            "squashfuse/fs.c",
            "squashfuse/fuseprivate.c",
            "squashfuse/stat.c",
            "squashfuse/dir.c",
            "squashfuse/file.c",
            "squashfuse/xattr.c",
            "squashfuse/nonstd-enoattr.c",
            "squashfuse/nonstd-makedev.c",
            "squashfuse/util.c",
            "squashfuse/nonstd-daemon.c",
            "squashfuse/nonstd-pread.c",
            "squashfuse/swap.c",
            "squashfuse/table.c",
            "squashfuse/cache_mt.c",
            "squashfuse/decompress.c",
            "squashfuse/nonstd-stat.c",
        },
        .flags = &[_][]const u8{
            "-Dmain=squashfuse_main",
            "-D_FILE_OFFSET_BITS=64",
        },
    });

    const clap = b.dependency("clap", .{
        .optimize = optimize,
        .target = target,
    });

    const squashfuse_autogen = b.addSystemCommand(&[_][]const u8{
        "./autogen.sh",
    });
    squashfuse_autogen.setCwd(b.path("squashfuse"));

    const squashfuse_configure = b.addSystemCommand(&[_][]const u8{
        "./configure",
        "--without-zlib",
        "--without-xz",
        "--without-lzo",
        "--without-lz4",
        "--with-zstd",
    });
    squashfuse_configure.setCwd(b.path("squashfuse"));
    squashfuse_configure.step.dependOn(&squashfuse_autogen.step);

    const squashfuse_make_generate_swap = b.addSystemCommand(&[_][]const u8{
        "make",
        "swap.h.inc",
        "swap.c.inc",
    });
    squashfuse_make_generate_swap.setCwd(b.path("squashfuse"));
    squashfuse_make_generate_swap.step.dependOn(&squashfuse_configure.step);

    const overlayfs_autogen = b.addSystemCommand(&[_][]const u8{
        "./autogen.sh",
    });
    overlayfs_autogen.setCwd(b.path("fuse-overlayfs"));

    const overlayfs_configure = b.addSystemCommand(&[_][]const u8{
        "./configure",
    });
    overlayfs_configure.setCwd(b.path("fuse-overlayfs"));
    overlayfs_configure.step.dependOn(&overlayfs_autogen.step);

    const libfuse_mkdir_build = b.addSystemCommand(&[_][]const u8{
        "mkdir",
        "-p",
        "build",
    });
    libfuse_mkdir_build.setCwd(b.path("libfuse"));

    const configure_libfuse = b.addSystemCommand(&[_][]const u8{
        "meson",
        "setup",
        "..",
    });
    configure_libfuse.setCwd(b.path("libfuse/build"));
    configure_libfuse.step.dependOn(&libfuse_mkdir_build.step);

    const runtime = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .optimize = optimize,
        .link_libc = true,
    });

    runtime.addImport("zstd", zstd);
    runtime.addImport("fuse-overlayfs", fuse_fss);

    runtime.addIncludePath(b.path("crun"));
    runtime.addIncludePath(b.path("crun/src"));
    runtime.addIncludePath(b.path("crun/libocispec/src"));

    runtime.addIncludePath(b.path("argp-standalone"));

    runtime.addCSourceFiles(.{
        .files = &[_][]const u8{
            "crun/src/libcrun/container.c",
            "crun/src/libcrun/status.c",
            "crun/src/libcrun/linux.c",
            "crun/src/libcrun/utils.c",
            "crun/src/libcrun/cgroup-utils.c",
            "crun/src/libcrun/cgroup.c",
            "crun/src/libcrun/intelrdt.c",
            "crun/src/libcrun/cgroup-resources.c",
            "crun/src/libcrun/ebpf.c",
            "crun/src/libcrun/cgroup-cgroupfs.c",
            "crun/src/libcrun/chroot_realpath.c",
            "crun/src/libcrun/cloned_binary.c",
            "crun/src/libcrun/custom-handler.c",
            "crun/src/libcrun/terminal.c",
            "crun/src/libcrun/cgroup-systemd.c",
            "crun/src/libcrun/error.c",
            "crun/src/libcrun/mount_flags.c",
            "crun/src/libcrun/seccomp.c",
            "crun/src/libcrun/seccomp_notify.c",
            "crun/src/libcrun/scheduler.c",
            "crun/src/libcrun/io_priority.c",
            "crun/src/libcrun/cgroup-setup.c",
            "crun/src/libcrun/signals.c",

            "crun/src/libcrun/blake3/blake3.c",
            "crun/src/libcrun/blake3/blake3_portable.c",

            "crun/libocispec/src/ocispec/read-file.c",
            "crun/libocispec/src/ocispec/json_common.c",
            "crun/libocispec/src/ocispec/runtime_spec_schema_config_schema.c",
            "crun/libocispec/src/ocispec/runtime_spec_schema_config_zos.c",
            "crun/libocispec/src/ocispec/runtime_spec_schema_config_vm.c",
            "crun/libocispec/src/ocispec/runtime_spec_schema_config_windows.c",
            "crun/libocispec/src/ocispec/runtime_spec_schema_config_solaris.c",
            "crun/libocispec/src/ocispec/runtime_spec_schema_config_linux.c",
            "crun/libocispec/src/ocispec/runtime_spec_schema_defs.c",
            "crun/libocispec/src/ocispec/runtime_spec_schema_defs_linux.c",
            "crun/libocispec/src/ocispec/runtime_spec_schema_defs_windows.c",
            "crun/libocispec/src/ocispec/runtime_spec_schema_defs_zos.c",

            "crun/libocispec/yajl/src/yajl.c",
            "crun/libocispec/yajl/src/yajl_gen.c",
            "crun/libocispec/yajl/src/yajl_buf.c",
            "crun/libocispec/yajl/src/yajl_alloc.c",
            "crun/libocispec/yajl/src/yajl_encode.c",
            "crun/libocispec/yajl/src/yajl_tree.c",
            "crun/libocispec/yajl/src/yajl_parser.c",
            "crun/libocispec/yajl/src/yajl_lex.c",
        },
    });

    const aarch64_target = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .abi = .musl,
        .os_tag = .linux,
    });

    const x86_64_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .abi = .musl,
        .os_tag = .linux,
    });

    const runtime_x86_64 = b.addExecutable(.{
        .name = "runtime_x86-64",
        .target = x86_64_target,
        .linkage = .static,
    });

    const runtime_aarch64 = b.addExecutable(.{
        .name = "runtime_aarch64",
        .target = aarch64_target,
        .linkage = .static,
    });

    runtime_x86_64.root_module.addImport("runtime", runtime);
    runtime_aarch64.root_module.addImport("runtime", runtime);

        const crun_autogen = b.addSystemCommand(&[_][]const u8{
            "./autogen.sh",
        });
        crun_autogen.setCwd(b.path("crun"));

        const crun_configure = b.addSystemCommand(&[_][]const u8{
            "./configure",
            "--enable-embedded-yajl",
            "--disable-systemd",
            "--disable-caps",
            "--disable-seccomp",
        });
        crun_configure.setCwd(b.path("crun"));
        crun_configure.step.dependOn(&crun_autogen.step);

    const libocspec_generate_files = b.addSystemCommand(&[_][]const u8{
            "make",
        "src/ocispec/runtime_spec_schema_config_schema.c",
        "src/ocispec/runtime_spec_schema_config_zos.c",
        "src/ocispec/runtime_spec_schema_config_vm.c",
        "src/ocispec/runtime_spec_schema_config_windows.c",
        "src/ocispec/runtime_spec_schema_config_solaris.c",
        "src/ocispec/runtime_spec_schema_config_linux.c",
        "src/ocispec/runtime_spec_schema_defs.c",
        "src/ocispec/runtime_spec_schema_defs_linux.c",
        "src/ocispec/runtime_spec_schema_defs_windows.c",
        "src/ocispec/runtime_spec_schema_defs_zos.c",
    });
    libocspec_generate_files.setCwd(b.path("crun/libocispec"));
    libocspec_generate_files.step.dependOn(&crun_configure.step);

    if (!skip_crun_build) {
        runtime_x86_64.step.dependOn(&squashfuse_make_generate_swap.step);
        runtime_x86_64.step.dependOn(&overlayfs_configure.step);
        runtime_x86_64.step.dependOn(&libocspec_generate_files.step);
        runtime_x86_64.step.dependOn(&configure_libfuse.step);

        runtime_aarch64.step.dependOn(&squashfuse_make_generate_swap.step);
        runtime_aarch64.step.dependOn(&overlayfs_configure.step);
        runtime_aarch64.step.dependOn(&libocspec_generate_files.step);
        runtime_aarch64.step.dependOn(&configure_libfuse.step);
    }

    const go_cpu_arch = switch (target.query.cpu_arch orelse target.result.cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => @panic("unimplemented"),
    };
    const umoci = b.addSystemCommand(&[_][]const u8{
        "go",
        "build",
        "-tags",
        "",
        "-ldflags",
        "-s -extldflags '-static'",
        "-o",
    });
    umoci.setCwd(b.path("umoci"));
    const umoci_output = umoci.addOutputFileArg("umoci");
    umoci.addArg("github.com/opencontainers/umoci/cmd/umoci");
    umoci.setEnvironmentVariable(
        "CGO_ENABLED",
        "0",
    );

    umoci.setEnvironmentVariable("GOARCH", go_cpu_arch);

    const skopeo = b.addSystemCommand(&[_][]const u8{
        "go",
        "build",
        "-gcflags",
        "",
        "-tags",
        "containers_image_openpgp",
        "-o",
    });
    skopeo.setCwd(b.path("skopeo"));
    const skopeo_output = skopeo.addOutputFileArg("skopeo");
    skopeo.addArg("./cmd/skopeo");

    skopeo.setEnvironmentVariable(
        "CGO_ENABLED",
        "0",
    );
    skopeo.setEnvironmentVariable("GOARCH", go_cpu_arch);
    skopeo.setEnvironmentVariable("DISABLE_DOCS", "1");

    const dockerc = b.addExecutable(.{
        .name = "dockerc",
        .root_source_file = b.path("src/dockerc.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    dockerc.addIncludePath(b.path("zstd/lib"));
    dockerc.root_module.addImport("zstd", zstd);
    dockerc.addCSourceFiles(.{
        .files = &[_][]const u8{
            "squashfs-tools/squashfs-tools/mksquashfs.c",
            "squashfs-tools/squashfs-tools/progressbar.c",
            "squashfs-tools/squashfs-tools/caches-queues-lists.c",
            "squashfs-tools/squashfs-tools/date.c",
            "squashfs-tools/squashfs-tools/pseudo.c",
            "squashfs-tools/squashfs-tools/action.c",
            "squashfs-tools/squashfs-tools/sort.c",
            "squashfs-tools/squashfs-tools/restore.c",
            "squashfs-tools/squashfs-tools/info.c",
            "squashfs-tools/squashfs-tools/mksquashfs_help.c",
            "squashfs-tools/squashfs-tools/print_pager.c",
            "squashfs-tools/squashfs-tools/compressor.c",
            "squashfs-tools/squashfs-tools/tar.c",
            "squashfs-tools/squashfs-tools/reader.c",
            "squashfs-tools/squashfs-tools/read_fs.c",
            "squashfs-tools/squashfs-tools/memory.c",
            "squashfs-tools/squashfs-tools/process_fragments.c",
            "squashfs-tools/squashfs-tools/zstd_wrapper.c",
        },
        .flags = &[_][]const u8{
            // avoid collision of main function
            "-Dmain=mksquashfs_main",
            "-DZSTD_SUPPORT",
            "-D_GNU_SOURCE",
            "-DVERSION=\"dockerc\"",
            "-DDATE=\"2024/07/21\"",
            "-DYEAR=\"2024\"",
            "-DCOMP_DEFAULT=\"zstd\"",
            "-DCOMPRESSORS=\"zstd\"",
            // There's UB in squashfs. This deals with it.
            "-fno-sanitize=undefined",
        },
    });

    dockerc.root_module.addAnonymousImport(
        "runtime_x86_64",
        .{ .root_source_file = runtime_x86_64.getEmittedBin() },
    );

    dockerc.root_module.addAnonymousImport(
        "runtime_aarch64",
        .{ .root_source_file = runtime_aarch64.getEmittedBin() },
    );

    dockerc.root_module.addAnonymousImport(
        "umoci",
        .{ .root_source_file = umoci_output },
    );
    dockerc.root_module.addAnonymousImport(
        "skopeo",
        .{ .root_source_file = skopeo_output },
    );

    dockerc.root_module.addImport("clap", clap.module("clap"));

    b.installArtifact(dockerc);

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    // b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    // const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    // run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    // if (b.args) |args| {
    //     run_cmd.addArgs(args);
    // }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    // const run_step = b.step("run", "Run the app");
    // run_step.dependOn(&run_cmd.step);
}
