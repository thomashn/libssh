# libssh
This is [libssh](https://www.libssh.org/),
packaged for [Zig](https://ziglang.org/).

## How to use it
First, update your `build.zig.zon`:

```
zig fetch --save git+https://github.com/thomashn/libssh#<commit>
```

Next, add this snippet to your `build.zig` script:
```zig
const libssh_dep = b.dependency("libssh", .{
    .target = target,
    .optimize = optimize,
});
your_compilation.linkLibrary(libssh_dep.artifact("libssh"));
```

This will provide libssh as a static library to `your_compilation`.

## How to run tests
libssh uses CMocka as its underlying C unit-testing framework. To compile and run the unit test suite, make sure you have `cmocka` installed on your host system:

* **Ubuntu/Debian:** `sudo apt install libcmocka-dev`
* **Fedora/RHEL:** `sudo dnf install libcmocka-devel`
* **Arch Linux:** `sudo pacman -S cmocka`
* **macOS (Homebrew):** `brew install cmocka`

Then run the tests on top of `mbedtls` using:
```bash
zig build test -Dunit_testing=true -Dmbedtls=true
```
