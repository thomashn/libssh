const std = @import("std");

const major = "0";
const minor = "11";
const patch = "1";
const version = major ++ "." ++ minor ++ "." ++ patch;

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
    const with_exec = b.option(bool, "exec", "Enable libssh to execute arbitrary commands from configuration files or options (match exec, proxy commands and OpenSSH-based proxy-jumps).") orelse true;
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

    const config = .{
        .PROJECT_NAME = "libssh",
        .PROJECT_VERSION = version,
        .SYSCONFDIR = "TODO",
        .BINARYDIR = "TODO",
        .SOURCEDIR = "TODO",
        .USR_GLOBAL_BIND_CONFIG = "TODO",
        .GLOBAL_BIND_CONFIG = "/etc/ssh/libssh_server_config",
        .USR_GLOBAL_CLIENT_CONFIG = "TODO",
        .GLOBAL_CLIENT_CONFIG = "/etc/ssh/ssh_config",
        .HAVE_ARGP_H = target.result.os.tag != .macos,
        .HAVE_ARPA_INET_H = 1,
        .HAVE_GLOB_H = 1,
        .HAVE_VALGRIND_VALGRIND_H = unit_testing,
        .HAVE_PTY_H = 1,
        .HAVE_UTMP_H = 1,
        .HAVE_UTIL_H = 0,
        .HAVE_LIBUTIL_H = 0,
        .HAVE_SYS_TIME_H = 1,
        .HAVE_SYS_UTIME_H = 0,
        .HAVE_IO_H = 1,
        .HAVE_TERMIOS_H = 1,
        .HAVE_UNISTD_H = 1,
        .HAVE_STDINT_H = 1,
        .HAVE_IFADDRS_H = 1,
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
        .HAVE_STRNDUP = 1,
        .HAVE_CFMAKERAW = 1,
        .HAVE_GETADDRINFO = 1,
        .HAVE_POLL = 1,
        .HAVE_SELECT = 1,
        .HAVE_CLOCK_GETTIME = 1,
        .HAVE_NTOHLL = 0,
        .HAVE_HTONLL = 0,
        .HAVE_STRTOULL = 1,
        .HAVE___STRTOULL = 1,
        .HAVE__STRTOUI64 = 1,
        .HAVE_GLOB = 1,
        .HAVE_EXPLICIT_BZERO = target.result.os.tag != .macos,
        .HAVE_MEMSET_S = 1,
        .HAVE_SECURE_ZERO_MEMORY = 1,
        .HAVE_CMOCKA_SET_TEST_FILTER = unit_testing,
        .HAVE_BLOWFISH = with_blowfish_cipher,
        .HAVE_LIBCRYPTO = with_openssl,
        .HAVE_LIBGCRYPT = with_gcrypt,
        .HAVE_LIBMBEDCRYPTO = with_mbedtls,
        // TODO Threading not working with zig mbedtls
        .HAVE_PTHREAD = !with_mbedtls,
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
        .WITH_EXEC = with_exec,
        .WITH_BLOWFISH_CIPHER = with_blowfish_cipher,
        .DEBUG_CRYPTO = with_debug_crypto,
        .DEBUG_PACKET = with_debug_packet,
        .WITH_PCAP = with_pcap,
        .DEBUG_CALLTRACE = with_debug_calltrace,
        .WITH_NACL = with_nacl,
        .WITH_PKCS11_URI = with_pkcs11_uri,
        .WITH_PKCS11_PROVIDER = with_pkcs11_provider,
        .WORDS_BIGENDIAN = 1,
    };

    const config_header = b.addConfigHeader(.{
        .style = .{
            .cmake = root.path(b, "config.h.cmake"),
        },
        .include_path = "config.h",
    }, config);

    const libssh = b.addStaticLibrary(.{
        .name = "libssh",
        .target = target,
        .optimize = optimize,
    });

    libssh.addConfigHeader(version_header);
    libssh.addConfigHeader(config_header);
    libssh.addIncludePath(root.path(b, "include"));
    libssh.installHeadersDirectory(root.path(b, "include"), ".", .{ .include_extensions = &.{ ".h", ".hpp" } });
    libssh.installConfigHeader(config_header);
    libssh.installConfigHeader(version_header);
    libssh.linkLibC();

    if (with_zlib) {
        const zlib = b.dependency("zlib", .{
            .target = target,
            .optimize = optimize,
        });
        libssh.linkLibrary(zlib.artifact("z"));
    }

    if (with_gcrypt) {
        libssh.linkSystemLibrary("gcrypt");
    }

    if (with_mbedtls) {
        const mbedtls = b.dependency("mbedtls", .{
            .target = target,
            .optimize = optimize,
        });
        libssh.linkLibrary(mbedtls.artifact("mbedtls"));
        libssh.installLibraryHeaders(mbedtls.artifact("mbedtls"));
    }

    if (with_openssl) {
        // At this point in time, the openssl zig package
        // only supports linux.
        if (target.result.os.tag == .linux) {
            const crypto = b.dependency("openssl", .{
                .target = target,
                .optimize = optimize,
            });
            libssh.linkLibrary(crypto.artifact("openssl"));
        } else {
            libssh.linkSystemLibrary("crypto");
        }
    }

    const libssh_src = root.path(b, "src");

    libssh.addCSourceFiles(.{
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
            "dh.c",
            "ecdh.c",
            "error.c",
            "getpass.c",
            "gzip.c",
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
            "options.c",
            "packet.c",
            "packet_cb.c",
            "packet_crypt.c",
            "pcap.c",
            "pki.c",
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
            libssh.addCSourceFiles(.{
                .root = libssh_src,
                .files = &.{
                    "threads/noop.c",
                    "threads/pthread.c",
                },
            });
        } else {
            libssh.addCSourceFiles(.{
                .root = libssh_src,
                .files = &.{
                    "threads/noop.c",
                    "threads/winlocks.c",
                },
            });
        }
    } else {
        libssh.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "threads/noop.c",
            },
        });
    }

    if (with_gcrypt) {
        libssh.addCSourceFiles(.{
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
            },
        });
        if (config.HAVE_GCRYPT_CHACHA_POLY) {
            libssh.addCSourceFiles(.{
                .root = libssh_src,
                .files = &.{
                    "external/chacha.c",
                    "external/poly1305.c",
                    "chachapoly.c",
                },
            });
        }
    } else if (with_mbedtls) {
        libssh.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "threads/mbedtls.c",
                "libmbedcrypto.c",
                "mbedcrypto_missing.c",
                "pki_mbedcrypto.c",
                "ecdh_mbedcrypto.c",
                "getrandom_mbedcrypto.c",
                "md_mbedcrypto.c",
                "dh_key.c",
                "pki_ed25519.c",
                "external/ed25519.c",
                "external/fe25519.c",
                "external/ge25519.c",
                "external/sc25519.c",
            },
        });
        // TODO FIX MISSING HAVE_MBEDTLS_CHACHA20_H, HAVE_MBEDTLS_POLY1305_H
        libssh.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "external/chacha.c",
                "external/poly1305.c",
                "chachapoly.c",
            },
        });
    } else {
        libssh.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "threads/libcrypto.c",
                "pki_crypto.c",
                "ecdh_crypto.c",
                "getrandom_crypto.c",
                "md_crypto.c",
                "libcrypto.c",
                "dh_crypto.c",
            },
        });
        if (!config.HAVE_OPENSSL_EVP_CHACHA20) {
            libssh.addCSourceFiles(.{
                .root = libssh_src,
                .files = &.{
                    "external/chacha.c",
                    "external/poly1305.c",
                    "chachapoly.c",
                },
            });
        }
    }

    if (with_sftp) {
        libssh.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "sftp.c",
                "sftp_common.c",
                "sftp_aio.c",
            },
        });
        if (with_server) {
            libssh.addCSourceFiles(.{
                .root = libssh_src,
                .files = &.{
                    "sftpserver.c",
                },
            });
        }
    }

    if (with_server) {
        libssh.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "server.c",
                "bind.c",
                "bind_config.c",
            },
        });
    }

    if (with_gex) {
        libssh.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "dh-gex.c",
            },
        });
    }

    if (with_gssapi) {
        libssh.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "gssapi.c",
            },
        });
    }

    if (!with_nacl) {
        libssh.addCSourceFiles(.{
            .root = libssh_src,
            .files = &.{
                "external/curve25519_ref.c",
            },
        });
    }

    b.installArtifact(libssh);

    if (with_examples) {
        const common = b.addSharedLibrary(.{
            .name = "common",
            .target = target,
            .optimize = optimize,
        });
        common.addCSourceFiles(.{
            .root = root.path(b, "examples"),
            .files = &.{
                "authentication.c",
                "knownhosts.c",
                "connect_ssh.c",
            },
        });
        common.linkLibrary(libssh);

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
                    .optimize = self.optimize,
                    .target = self.target,
                });
                const is_cpp = comptime std.mem.containsAtLeast(u8, name, 1, "hpp");
                const path = if (is_cpp) "examples/" ++ name ++ ".cpp" else "examples/" ++ name ++ ".c";
                exe.addCSourceFile(.{ .file = self.root.path(self.b, path) });
                exe.linkLibrary(self.common);
                exe.linkLibrary(self.libssh);
                if (is_cpp) {
                    // exe.addIncludePath(self.root.path(self.b, "include"));
                    exe.linkLibCpp();
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

        examples.add("exec");
        examples.add("keygen");
        examples.add("keygen2");
        examples.add("libssh_scp");
        // examples.add("proxy"); TODO Enable gssapi
        examples.add("sample_sftpserver");
        examples.add("samplesftp");
        examples.add("samplesshd-cb");
        examples.add("samplesshd-kbdint");
        examples.add("scp_download");
        examples.add("senddata");
        examples.add("ssh_X11_client");
        examples.add("ssh_client");
        examples.add("ssh_server");
        // examples.add("sshd_direct-tcpip"); TODO Enable gssapi
        examples.add("sshnetcat");
        examples.add("libsshpp");
        examples.add("libsshpp_noexcept");
    }
}
