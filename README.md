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
