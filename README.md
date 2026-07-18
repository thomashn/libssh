# libssh
[![Zig Version](https://img.shields.io/badge/Zig-0.16.0-orange.svg?logo=zig)](https://ziglang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

This is [libssh](https://www.libssh.org/),
packaged for [Zig](https://ziglang.org/).

## How to use it
First, update your `build.zig.zon`:

```
zig fetch --save git+https://github.com/thomashn/libssh#<commit|tag>
```

Next, add this snippet to your `build.zig` script:
```zig
const libssh_dep = b.dependency("libssh", .{
    .target = target,
    .optimize = optimize,
    // The Zig mbedtls is preferred because it is more complete
    .mbedtls = true,
});
your_compilation.linkLibrary(libssh_dep.artifact("libssh"));
```

This will provide libssh as a static library to `your_compilation`.

## Run tests
Run all [cmocka](https://cmocka.org/) libssh tests that do not require external processes.
```bash
zig build test -Dunit_testing=true -Dmbedtls=true
```
