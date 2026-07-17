const std = @import("std");

const major = 0;
const minor = 12;
const patch = 0;
const version = std.fmt.comptimePrint("{}.{}.{}", .{ major, minor, patch });

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const with_gssapi = b.option(bool, "gssapi", "Build with GSSAPI support") orelse false; // CHANGED
    const with_zlib = b.option(bool, "zlib", "Build with ZLIB support") orelse true;
    const with_sftp = b.option(bool, "sftp", "Build with SFTP support") orelse true;
    const with_server = b.option(bool, "server", "Build with SSH server support") orelse true;
    const with_debug_crypto = b.option(bool, "debug_crypto", "Build with crypto debug output") orelse false;
    const with_debug_packet = b.option(bool, "debug_packet", "Build with packet debug output") orelse false;
    const with_debug_calltrace = b.option(bool, "debug_calltrace", "Build with calltrace debug output") orelse true;
    const with_gcrypt = b.option(bool, "gcrypt", "Compile against libgcrypt (deprecated)") orelse false;
    const with_mbedtls = b.option(bool, "mbedtls", "Compile against libmbedtls") orelse false;
    const with_blowfish_cipher = b.option(bool, "blowfish", "Compile with blowfish support") orelse false;
    const with_pcap = b.option(bool, "pcap", "Compile with Pcap generation support") orelse true;
    const with_internal_doc = b.option(bool, "internal_doc", "Compile doxygen internal documentation") orelse false;
    const with_pkcs11_uri = b.option(bool, "pkcs11_uri", "Build with PKCS#11 support") orelse false;
    const with_pkcs11_provider = b.option(bool, "pkcs11_provider", "Use the PKCS#11 provider for accessing pkcs11 objects") orelse false;
    const unit_testing = b.option(bool, "unit_testing", "Build with unit tests") orelse false;
    const client_testing = b.option(bool, "client_testing", "Build with client tests; requires openssh") orelse false;
    const server_testing = b.option(bool, "server_testing", "Build with server tests; requires openssh and dropbear") orelse false;
    const gssapi_testing = b.option(bool, "gssapi_testing", "Build with GSSAPI tests; requires krb5-server,krb5-libs and krb5-workstation") orelse false;
    const with_benchmarks = b.option(bool, "benchmarks", "Build benchmarks tools; enables unit testing and client tests") orelse false;
    const with_examples = b.option(bool, "examples", "Build examples") orelse false; // CHANGED
    const with_nacl = b.option(bool, "nacl", "Build with libnacl (curve25519)") orelse false; // CHANGED
    const with_symbol_versioning = b.option(bool, "symbol_versioning", "Build with symbol versioning") orelse false; //CHANGED
    const with_abi_break = b.option(bool, "abi_break", "Allow ABI break") orelse false;
    const with_gex = b.option(bool, "gex", "Enable DH Group exchange mechanisms") orelse true;
    const with_insecure_none = b.option(bool, "insecure_none", "Enable insecure none cipher and MAC algorithms (not suitable for production!)") orelse false;
    const with_exec = b.option(bool, "exec", "Enable libssh to execute arbitrary commands from configuration files or options (match exec, proxy commands and OpenSSH-based proxy-jumps).");
    const fuzz_testing = b.option(bool, "fuzz_testing", "Build with fuzzer for the server and client (automatically enables none chiper!)") orelse false;
    const picky_developer = b.option(bool, "picky_developer", "Build with picky developer flags") orelse false;
    const with_hermetic_usr = b.option(bool, "hermetic_usr", "Build with support for hermetic /usr/") orelse false;

    // Not implemented options
    if (with_gssapi or with_internal_doc or client_testing or server_testing or gssapi_testing or with_benchmarks or with_nacl or with_symbol_versioning or with_abi_break or fuzz_testing or picky_developer or with_hermetic_usr) {
        @panic("You enabled an option that has yet to be implemented in the Zig build system");
    }

    if (with_gcrypt and with_mbedtls) {
        @panic("You cannot select both gcrypt and mbedtls at the same time");
    }
    const with_openssl = !(with_mbedtls or with_gcrypt);

    const c_libssh = b.dependency("libssh", .{});

    const version_conf = .{
        .libssh_VERSION_MAJOR = major,
        .libssh_VERSION_MINOR = minor,
        .libssh_VERSION_PATCH = patch,
    };

    const root = c_libssh.path("");

    const version_header = b.addConfigHeader(.{
        .style = .{
            .cmake = root.path(b, "include/libssh/libssh_version.h.cmake"),
        },
        .include_path = "libssh/libssh_version.h",
    }, version_conf);

    const have_argp = target.result.os.tag == .linux and target.result.abi != .musl;
    const have_libutil = false;
    const have_pty = target.result.os.tag == .linux;
    const is_unix = target.result.os.tag == .linux or target.result.os.tag == .macos;
    const is_windows = target.result.os.tag == .windows;

    var enable_exec: bool = undefined;
    if (with_exec) |exe| {
        if (exe == true and is_windows) @panic("exec is unsupported on Windows");
        enable_exec = exe;
    } else {
        enable_exec = !is_windows;
    }

    const config = .{
        .PROJECT_NAME = "libssh",
        .PROJECT_VERSION = version,
        .SYSCONFDIR = "TODO",
        .BINARYDIR = "TODO",
        .SOURCEDIR = root.getPath(b),
        .USR_GLOBAL_BIND_CONFIG = "TODO",
        .USR_GLOBAL_CONF_DIR = "TODO",
        .GLOBAL_CONF_DIR = "TODO",
        .GLOBAL_BIND_CONFIG = "/etc/ssh/libssh_server_config",
        .USR_GLOBAL_CLIENT_CONFIG = "TODO",
        .GLOBAL_CLIENT_CONFIG = "/etc/ssh/ssh_config",
        .HAVE_ARGP_H = have_argp,
        .HAVE_ARPA_INET_H = is_unix,
        .HAVE_GLOB_H = is_unix,
        .HAVE_VALGRIND_VALGRIND_H = false,
        .HAVE_PTY_H = have_pty,
        .HAVE_UTMP_H = 1,
        .HAVE_UTIL_H = target.result.os.tag == .macos,
        .HAVE_LIBUTIL_H = have_libutil,
        .HAVE_SYS_TIME_H = 1,
        .HAVE_SYS_UTIME_H = 0,
        .HAVE_IO_H = 1,
        .HAVE_TERMIOS_H = is_unix,
        .HAVE_UNISTD_H = 1,
        .HAVE_STDINT_H = 1,
        .HAVE_IFADDRS_H = is_unix,
        .HAVE_OPENSSL_AES_H = with_openssl,
        .HAVE_WSPIAPI_H = 1,
        .HAVE_OPENSSL_DES_H = with_openssl,
        .HAVE_OPENSSL_ECDH_H = with_openssl,
        .HAVE_OPENSSL_EC_H = with_openssl,
        .HAVE_OPENSSL_ECDSA_H = with_openssl,
        .HAVE_PTHREAD_H = 1,
        .HAVE_OPENSSL_ECC = with_openssl,
        .HAVE_GCRYPT_ECC = with_gcrypt,
        .HAVE_ECC = 1,
        .HAVE_GLOB_GL_FLAGS_MEMBER = target.result.abi != .musl,
        .HAVE_GCRYPT_CHACHA_POLY = with_gcrypt,
        .HAVE_OPENSSL_EVP_CHACHA20 = with_openssl,
        .HAVE_OPENSSL_EVP_KDF_CTX = with_openssl,
        .HAVE_OPENSSL_FIPS_MODE = with_openssl and false, // TODO Fix
        .HAVE_SNPRINTF = 1,
        .HAVE__SNPRINTF = 1,
        .HAVE__SNPRINTF_S = 1,
        .HAVE_VSNPRINTF = 1,
        .HAVE__VSNPRINTF = 1,
        .HAVE__VSNPRINTF_S = 1,
        .HAVE_ISBLANK = 1,
        .HAVE_STRNCPY = 1,
        .HAVE_STRNDUP = is_unix,
        .HAVE_CFMAKERAW = 1,
        .HAVE_GETADDRINFO = 1,
        .HAVE_POLL = is_unix,
        .HAVE_SELECT = 1,
        .HAVE_CLOCK_GETTIME = 1,
        .HAVE_NTOHLL = 0,
        .HAVE_HTONLL = 0,
        .HAVE_STRTOULL = 1,
        .HAVE___STRTOULL = 1,
        .HAVE__STRTOUI64 = 1,
        .HAVE_GLOB = is_unix,
        .HAVE_EXPLICIT_BZERO = target.result.os.tag == .linux,
        .HAVE_MEMSET_EXPLICIT = false,
        .HAVE_MEMSET_S = is_unix,
        .HAVE_SECURE_ZERO_MEMORY = 1,
        .HAVE_CMOCKA_SET_TEST_FILTER = unit_testing,
        .HAVE_BLOWFISH = with_blowfish_cipher,
        .HAVE_LIBCRYPTO = with_openssl,
        .HAVE_LIBGCRYPT = with_gcrypt,
        .HAVE_LIBMBEDCRYPTO = with_mbedtls,
        .HAVE_MBEDTLS_CURVE25519 = with_mbedtls,
        .HAVE_PTHREAD = !is_windows,
        .HAVE_CMOCKA = unit_testing,
        .HAVE_GCC_THREAD_LOCAL_STORAGE = 0,
        .HAVE_MSC_THREAD_LOCAL_STORAGE = 0,
        .HAVE_FALLTHROUGH_ATTRIBUTE = 1,
        .HAVE_UNUSED_ATTRIBUTE = 1,
        .HAVE_WEAK_ATTRIBUTE = 1,
        .HAVE_CONSTRUCTOR_ATTRIBUTE = 1,
        .HAVE_DESTRUCTOR_ATTRIBUTE = 1,
        .HAVE_GCC_VOLATILE_MEMORY_PROTECTION = 0,
        .HAVE_COMPILER__FUNC__ = 1,
        .HAVE_COMPILER__FUNCTION__ = 1,
        .HAVE_GCC_BOUNDED_ATTRIBUTE = 0,
        .WITH_GSSAPI = with_gssapi,
        .WITH_ZLIB = with_zlib,
        .WITH_SFTP = with_sftp,
        .WITH_SERVER = with_server,
        .WITH_GEX = with_gex,
        .WITH_INSECURE_NONE = with_insecure_none,
        .WITH_EXEC = enable_exec,
        .WITH_BLOWFISH_CIPHER = with_blowfish_cipher,
        .DEBUG_CRYPTO = with_debug_crypto,
        .DEBUG_PACKET = with_debug_packet,
        .WITH_PCAP = with_pcap,
        .DEBUG_CALLTRACE = with_debug_calltrace,
        .WITH_NACL = with_nacl,
        .WITH_PKCS11_URI = with_pkcs11_uri,
        .WITH_PKCS11_PROVIDER = with_pkcs11_provider,
        .WORDS_BIGENDIAN = if (target.result.cpu.arch.endian() == .big) @as(u32, 1) else @as(u32, 0),
        .HAVE_OPENSSL_MLKEM = false,
        .HAVE_GCRYPT_MLKEM = false,
        .HAVE_MLKEM1024 = false,
    };

    const config_header = b.addConfigHeader(.{
        .style = .{
            .cmake = root.path(b, "config.h.cmake"),
        },
        .include_path = "config.h",
    }, config);

    const libssh = b.addLibrary(.{
        .name = "libssh",
        .version = .{
            .major = major,
            .minor = minor,
            .patch = patch,
        },
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .static,
    });

    if (is_windows) {
        libssh.root_module.addCMacro("_WIN32", "1");
    }
    libssh.root_module.addCMacro("LIBSSH_STATIC", "1");

    libssh.root_module.addConfigHeader(version_header);
    libssh.root_module.addConfigHeader(config_header);
    libssh.root_module.addIncludePath(root.path(b, "include"));
    libssh.installHeadersDirectory(root.path(b, "include"), ".", .{ .include_extensions = &.{ ".h", ".hpp" } });
    libssh.installConfigHeader(config_header);
    libssh.installConfigHeader(version_header);
    libssh.root_module.link_libc = true;

    if (with_zlib) {
        const zlib = b.dependency("zlib", .{
            .target = target,
            .optimize = optimize,
        });
        libssh.root_module.linkLibrary(zlib.artifact("z"));
    }

    if (with_gcrypt) {
        libssh.root_module.linkSystemLibrary("gcrypt", .{});
    }

    if (with_mbedtls) {
        const mbedtls = b.dependency("mbedtls", .{
            .target = target,
            .optimize = optimize,
            .threading = true,
        });
        libssh.root_module.linkLibrary(mbedtls.artifact("mbedtls"));
        libssh.installLibraryHeaders(mbedtls.artifact("mbedtls"));
        libssh.root_module.addCMacro("MBEDTLS_THREADING_C", "1");
        libssh.root_module.addCMacro("MBEDTLS_THREADING_PTHREAD", "1");
    }

    if (with_openssl) {
        // At this point in time, the openssl zig package
        // only supports linux.
        if (target.result.os.tag == .linux) {
            const crypto = b.dependency("openssl", .{
                .target = target,
                .optimize = optimize,
            });
            libssh.root_module.linkLibrary(crypto.artifact("openssl"));
        } else {
            libssh.root_module.linkSystemLibrary("crypto", .{});
        }
    }

    const libssh_src = root.path(b, "src");

    libssh.root_module.addCSourceFiles(.{
        .root = libssh_src,
        .files = &.{
            "agent.c",
            "auth.c",
            "base64.c",
            "bignum.c",
            "buffer.c",
            "callbacks.c",
            "channels.c",
            "client.c",
            "config.c",
            "connect.c",
            "connector.c",
            "crypto_common.c",
            "curve25519.c",
            "sntrup761.c",
            "dh.c",
            "ecdh.c",
            "error.c",
            "getpass.c",
            "gzip.c",
            "hybrid_mlkem.c",
            "init.c",
            "kdf.c",
            "kex.c",
            "known_hosts.c",
            "knownhosts.c",
            "legacy.c",
            "log.c",
            "match.c",
            "messages.c",
            "misc.c",
            "mlkem.c",
            "options.c",
            "packet.c",
            "packet_cb.c",
            "packet_crypt.c",
            "pcap.c",
            "pki.c",
            "pki_context.c",
            "pki_container_openssh.c",
            "poll.c",
            "session.c",
            "scp.c",
            "socket.c",
            "string.c",
            "threads.c",
            "ttyopts.c",
            "wrapper.c",
            "external/bcrypt_pbkdf.c",
            "external/blowfish.c",
            "config_parser.c",
            "token.c",
            "pki_ed25519_common.c",
        },
    });

    if (config.HAVE_PTHREAD) {
        if (target.result.os.tag == .linux or target.result.os.tag == .macos) {
            libssh.root_module.addCSourceFiles(.{
                .root = libssh_src,
                .files = &.{
                    "threads/noop.c",
                    "threads/pthread.c",
                },
            });
        } else {
            libssh.root_module.addCSourceFiles(.{
                .root = libssh_src,
                .files = &.{
                    "threads/noop.c",
                    "threads/winlocks.c",
                },
            });
        }
    } else {
        libssh.root_module.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "threads/noop.c",
            },
        });
    }

    if (with_gcrypt) {
        libssh.root_module.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "threads/libgcrypt.c",
                "libgcrypt.c",
                "gcrypt_missing.c",
                "pki_gcrypt.c",
                "ecdh_gcrypt.c",
                "getrandom_gcrypt.c",
                "md_gcrypt.c",
                "dh_key.c",
                "pki_ed25519.c",
                "external/ed25519.c",
                "external/fe25519.c",
                "external/ge25519.c",
                "external/sc25519.c",
                "external/sntrup761.c",
            },
        });
        if (config.HAVE_GCRYPT_CHACHA_POLY) {
            libssh.root_module.addCSourceFiles(.{
                .root = libssh_src,
                .files = &.{
                    "external/chacha.c",
                    "external/poly1305.c",
                    "chachapoly.c",
                },
            });
        }
        if (config.HAVE_GCRYPT_MLKEM) {
            libssh.root_module.addCSourceFiles(.{
                .root = libssh_src,
                .files = &.{
                    "mlkem_gcrypt.c",
                },
            });
        }
    } else if (with_mbedtls) {
        libssh.root_module.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "threads/mbedtls.c",
                "libmbedcrypto.c",
                "mbedcrypto_missing.c",
                "pki_mbedcrypto.c",
                "ecdh_mbedcrypto.c",
                "curve25519_mbedcrypto.c",
                "getrandom_mbedcrypto.c",
                "md_mbedcrypto.c",
                "dh_key.c",
                "pki_ed25519.c",
                "external/ed25519.c",
                "external/fe25519.c",
                "external/ge25519.c",
                "external/sc25519.c",
                "external/sntrup761.c",
            },
        });
        // TODO FIX MISSING HAVE_MBEDTLS_CHACHA20_H, HAVE_MBEDTLS_POLY1305_H
        libssh.root_module.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "external/chacha.c",
                "external/poly1305.c",
                "chachapoly.c",
            },
        });
    } else {
        libssh.root_module.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "threads/libcrypto.c",
                "pki_crypto.c",
                "ecdh_crypto.c",
                "curve25519_crypto.c",
                "getrandom_crypto.c",
                "md_crypto.c",
                "libcrypto.c",
                "dh_crypto.c",
                "external/sntrup761.c",
            },
        });
        if (!config.HAVE_OPENSSL_EVP_CHACHA20) {
            libssh.root_module.addCSourceFiles(.{
                .root = libssh_src,
                .files = &.{
                    "external/chacha.c",
                    "external/poly1305.c",
                    "chachapoly.c",
                },
            });
        }
        if (config.HAVE_OPENSSL_MLKEM) {
            libssh.root_module.addCSourceFiles(.{
                .root = libssh_src,
                .files = &.{
                    "mlkem_crypto.c",
                },
            });
        }
    }

    if (with_sftp) {
        libssh.root_module.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "sftp.c",
                "sftp_common.c",
                "sftp_aio.c",
            },
        });
        if (with_server) {
            libssh.root_module.addCSourceFiles(.{
                .root = libssh_src,
                .files = &.{
                    "sftpserver.c",
                },
            });
        }
    }

    if (with_server) {
        libssh.root_module.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "server.c",
                "bind.c",
                "bind_config.c",
            },
        });
    }

    if (with_gex) {
        libssh.root_module.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "dh-gex.c",
            },
        });
    }

    if (with_gssapi) {
        libssh.root_module.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "gssapi.c",
            },
        });
    }

    if (!with_nacl) {
        libssh.root_module.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "external/curve25519_ref.c",
            },
        });
    }

    if (!config.HAVE_MLKEM1024) {
        libssh.root_module.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "mlkem_native.c",
                "external/libcrux_mlkem768_sha3.c",
            },
        });
    }

    b.installArtifact(libssh);

    if (unit_testing) {
        const tests_config = .{
            .OPENSSH_VERSION_MAJOR = @as(?[]const u8, null),
            .OPENSSH_VERSION_MINOR = @as(?[]const u8, null),
            .OPENSSH_SUPPORTS_SSHSIG = @as(?[]const u8, null),
            .OPENSSH_CIPHERS = "",
            .OPENSSH_MACS = "",
            .OPENSSH_KEX = "",
            .OPENSSH_KEYS = "",
            .NCAT_EXECUTABLE = "",
            .SSHD_EXECUTABLE = "",
            .SSH_EXECUTABLE = "",
            .SSH_EXECUTABLE_SIZE = @as(?[]const u8, null),
            .SSH_KEYGEN_EXECUTABLE = "",
            .DROPBEAR_EXECUTABLE = "",
            .PUTTY_EXECUTABLE = "",
            .PUTTYGEN_EXECUTABLE = "",
            .WITH_TIMEOUT = @as(?[]const u8, null),
            .TIMEOUT_EXECUTABLE = "",
            .SOFTHSM2_LIBRARY = "",
            .PKCS11SPY = "",
            .SK_DUMMY_LIBRARY_PATH = "",
        };

        const tests_config_header = b.addConfigHeader(.{
            .style = .{
                .cmake = root.path(b, "tests/tests_config.h.cmake"),
            },
            .include_path = "tests_config.h",
        }, tests_config);

        const torture = b.addLibrary(.{
            .name = "torture",
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
            }),
            .linkage = .static,
        });
        torture.root_module.addConfigHeader(config_header);
        torture.root_module.addConfigHeader(version_header);
        torture.root_module.addConfigHeader(tests_config_header);
        torture.root_module.addIncludePath(root.path(b, "include"));
        torture.root_module.addIncludePath(root.path(b, "tests"));
        torture.root_module.addIncludePath(root.path(b, "src"));
        torture.root_module.linkLibrary(libssh);
        torture.root_module.link_libc = true;
        torture.root_module.linkSystemLibrary("cmocka", .{});
        torture.root_module.addCMacro("LIBSSH_STATIC", "1");
        torture.root_module.addCMacro("SSH_PING_EXECUTABLE", "\"ssh_ping\"");

        torture.root_module.addCSourceFiles(.{
            .root = root.path(b, "tests"),
            .files = &.{
                "cmdline.c",
                "torture.c",
                "torture_key.c",
                "torture_pki.c",
                "torture_sk.c",
                "torture_cmocka.c",
            },
        });

        var unit_tests: std.ArrayList([]const u8) = .empty;
        defer unit_tests.deinit(b.allocator);

        unit_tests.appendSlice(b.allocator, &.{
            "torture_bignum",
            "torture_buffer",
            "torture_bytearray",
            "torture_callbacks",
            "torture_crypto",
            "torture_init",
            "torture_list",
            "torture_misc",
            "torture_config",
            "torture_options",
            "torture_isipaddr",
            "torture_knownhosts_parsing",
            "torture_hashes",
            "torture_packet_filter",
            "torture_temp_dir",
            "torture_temp_file",
            "torture_push_pop_dir",
            "torture_session_keys",
            "torture_string",
            "torture_tokens",
        }) catch @panic("OOM");

        if (config.HAVE_PTHREAD) {
            unit_tests.appendSlice(b.allocator, &.{
                "torture_rand",
                "torture_threads_init",
                "torture_threads_buffer",
                "torture_threads_crypto",
            }) catch @panic("OOM");
        }

        if (is_unix) {
            unit_tests.appendSlice(b.allocator, &.{
                "torture_packet",
                "torture_keyfiles",
                "torture_pki",
                "torture_pki_rsa",
                "torture_pki_dsa",
                "torture_pki_ed25519",
                "torture_pki_sk_ed25519",
                "torture_pki_sshsig",
                "torture_channel",
                "torture_pki_ecdsa",
                "torture_pki_sk_ecdsa",
            }) catch @panic("OOM");

            if (config.HAVE_PTHREAD) {
                unit_tests.append(b.allocator, "torture_threads_pki_rsa") catch @panic("OOM");
            }

            if (is_unix) { // HAVE_IFADDRS_H is true on Unix in config
                unit_tests.append(b.allocator, "torture_config_match_localnetwork") catch @panic("OOM");
            }

            if (with_server) {
                unit_tests.append(b.allocator, "torture_bind_config") catch @panic("OOM");
                if (config.HAVE_PTHREAD) {
                    unit_tests.appendSlice(b.allocator, &.{
                        "torture_unit_server",
                        "torture_server_x11",
                        "torture_forwarded_tcpip_callback",
                        "torture_server_direct_tcpip",
                    }) catch @panic("OOM");
                }
                if (with_gex) {
                    unit_tests.append(b.allocator, "torture_moduli") catch @panic("OOM");
                }
            }
        }

        if (with_sftp) {
            unit_tests.append(b.allocator, "torture_unit_sftp") catch @panic("OOM");
        }

        const test_step = b.step("test", "Run unit tests");

        for (unit_tests.items) |name| {
            const exe = b.addExecutable(.{
                .name = name,
                .root_module = b.createModule(.{
                    .target = target,
                    .optimize = optimize,
                }),
            });
            exe.root_module.addConfigHeader(config_header);
            exe.root_module.addConfigHeader(version_header);
            exe.root_module.addConfigHeader(tests_config_header);
            exe.root_module.addIncludePath(root.path(b, "include"));
            exe.root_module.addIncludePath(root.path(b, "tests"));
            exe.root_module.addIncludePath(root.path(b, "src"));

            exe.root_module.linkLibrary(libssh);
            exe.root_module.linkLibrary(torture);
            exe.root_module.linkSystemLibrary("cmocka", .{});
            exe.root_module.link_libc = true;

            // Many unit tests directly `#include "some_file.c"` to test internal static functions,
            // which creates duplicate symbol conflicts with the built libssh archive. LLVM's LLD
            // is strictly intolerant of this, whereas host-standard GNU ld/linkers natively allow
            // local object overrides (matching the original CMake test build behavior).
            exe.use_lld = false;

            const path = b.fmt("tests/unittests/{s}.c", .{name});
            exe.root_module.addCSourceFile(.{ .file = root.path(b, path) });

            const run = b.addRunArtifact(exe);
            test_step.dependOn(&run.step);
        }
    }

    if (with_examples) {
        const common = b.addLibrary(.{
            .name = "common",
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
            }),
            .linkage = .static,
        });
        common.root_module.addCSourceFiles(.{
            .root = root.path(b, "examples"),
            .files = &.{
                "authentication.c",
                "knownhosts.c",
                "connect_ssh.c",
            },
        });
        common.root_module.linkLibrary(libssh);
        //b.installArtifact(common);

        const Examples = struct {
            b: *std.Build,
            optimize: std.builtin.OptimizeMode,
            target: std.Build.ResolvedTarget,
            common: *std.Build.Step.Compile,
            libssh: *std.Build.Step.Compile,
            root: std.Build.LazyPath,

            pub fn add(self: @This(), comptime name: []const u8) void {
                const exe = self.b.addExecutable(.{
                    .name = name,
                    .root_module = self.b.createModule(.{
                        .optimize = self.optimize,
                        .target = self.target,
                    }),
                });
                const is_cpp = comptime std.mem.containsAtLeast(u8, name, 1, "hpp");
                const path = if (is_cpp) "examples/" ++ name ++ ".cpp" else "examples/" ++ name ++ ".c";
                exe.root_module.addCSourceFile(.{ .file = self.root.path(self.b, path) });
                exe.root_module.linkLibrary(self.common);
                exe.root_module.linkLibrary(self.libssh);
                if (is_cpp) {
                    exe.root_module.link_libcpp = true;
                }
                self.b.installArtifact(exe);
            }
        };

        const examples = Examples{
            .b = b,
            .optimize = optimize,
            .target = target,
            .libssh = libssh,
            .common = common,
            .root = root,
        };

        if (is_unix) {
            examples.add("libssh_scp");
            examples.add("scp_download");
            examples.add("sshnetcat");

            if (with_sftp) {
                examples.add("samplesftp");
                if (with_server) {
                    examples.add("sample_sftpserver");
                }
            }

            examples.add("ssh_client");
            examples.add("ssh_X11_client");

            if (with_server and (have_argp)) {
                if (have_libutil) {
                    examples.add("ssh_server");
                }
                if (with_gssapi) {
                    examples.add("proxy");
                    examples.add("sshd_direct-tcpip");
                }
                examples.add("samplesshd-kbdint");
                examples.add("keygen2");
            }

            if (with_server) {
                examples.add("samplesshd-cb");
            }

            examples.add("exec");
            examples.add("senddata");
            examples.add("keygen");
            examples.add("libsshpp");
            examples.add("libsshpp_noexcept");
        }
    }
}
