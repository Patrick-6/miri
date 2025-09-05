# **(WIP)** Documentation for Miri-GenMC

[GenMC](https://github.com/MPI-SWS/genmc) is a stateless model checker for exploring concurrent executions of a program.
Miri-GenMC integrates that model checker into Miri.

**NOTE: Currently, no actual GenMC functionality is part of Miri, this is still WIP.**

<!-- FIXME(genmc): add explanation. -->

## Usage

For testing/developing Miri-GenMC:
- clone the Miri repo.
- build Miri-GenMC with `./miri build --features=genmc`.
- OR: install Miri-GenMC in the current system with `./miri install --features=genmc`

Basic usage:
```shell
MIRIFLAGS="-Zmiri-genmc" cargo miri run
```

Note that `cargo miri test` in GenMC mode is currently not supported.

### Supported Parameters

- `-Zmiri-genmc`: Enable GenMC mode (not required if any other GenMC options are used).
- `-Zmiri-genmc-log=LOG_LEVEL`: Change the log level for GenMC. Default: `warning`.
  - `quiet`:    Disable logging.
  - `error`:    Print errors.
  - `warning`:  Print errors and warnings.
  - `tip`:      Print errors, warnings and tips.
  - If Miri is built with debug assertions, there are additional log levels available (downgraded to `tip` without debug assertions):
    - `debug1`:   Print revisits considered by GenMC.
    - `debug2`:   Print the execution graph after every memory access.
    - `debug3`:   Print reads-from values considered by GenMC.

<!-- FIXME(genmc): explain options. -->

<!-- FIXME(genmc): explain Miri-GenMC specific functions. -->

## Tips

<!-- FIXME(genmc): add tips for using Miri-GenMC more efficiently. -->

## Limitations

Some or all of these limitations might get removed in the future:

- Borrow tracking is currently incompatible (stacked/tree borrows).
- Only Linux and MacOS are supported for now.
- No support for 32-bit or big-endian targets.
- No cross-target interpretation.

<!-- FIXME(genmc): document remaining limitations -->

## Development

GenMC is written in C++, which complicates development a bit.
The prerequisites for building Miri-GenMC are:
- A compiler with C++23 support.
- LLVM developments headers and clang.
  <!-- FIXME(genmc,llvm): remove once LLVM dependency is no longer required. -->

The actual code for GenMC is not contained in the Miri repo itself, but in a [separate GenMC repo](https://github.com/MPI-SWS/genmc) (with its own maintainers).
These sources need to be available to build Miri-GenMC.
The process for obtaining them is as follows:
- By default, a fixed commit of GenMC is downloaded to `genmc-sys/genmc-src` and built automatically.
  (The commit is determined by `GENMC_COMMIT` in `genmc-sys/build.rs`.)
- If you want to overwrite that, set the `GENMC_SRC_PATH` environment variable to a path that contains the GenMC sources.
  If you place this directory inside the Miri folder, it is recommended to call it `genmc-src` as that tells `./miri fmt` to avoid
  formatting the Rust files inside that folder.

### Formatting the C++ code

For formatting the C++ code we provide a `.clang-format` file in the `genmc-sys` directory.
With `clang-format` installed, run this command to format the c++ files (replace the `-i` with `--dry-run` to just see the changes.):
```
find ./genmc-sys/cpp/ -name "*.cpp" -o -name "*.hpp" | xargs clang-format --style=file:"./genmc-sys/.clang-format" -i
```
NOTE: this is currently not done automatically on pull requests to Miri.

<!-- FIXME(genmc): explain how submitting code to GenMC should be handled. -->

<!-- FIXME(genmc): explain development. -->
