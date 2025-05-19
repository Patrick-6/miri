use std::ffi::os_str;
use std::path::PathBuf;
use std::process::Command;

use walkdir::WalkDir;

fn main() {
    // Build the project in the path `foo` and installs it in `$OUT_DIR`
    // let dst = autotools::build("genmc");

    let make_command_num_threads = num_cpus::get();

    const LLVM_PATH: &str = "/usr/lib/llvm-19/lib";

    // TODO GENMC: is this still required?
    let mut genmc_path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    genmc_path.pop();
    genmc_path.push("genmc");

    let mut genmc_src_path = genmc_path.clone();
    genmc_src_path.push("src");

    let mut miri_genmc_interface_path = genmc_src_path.clone();
    miri_genmc_interface_path.extend(["Verification", "MiriInterface.hpp"]);

    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap();
    let cxx_bridge_include_path: PathBuf = [&target_dir, "cxxbridge"].into_iter().collect();

    /// Rust source file containing the #[cxx::bridge] code for GenMC interop.
    const RUST_CXX_BRIDGE_FILE_PATH: &str = "src/lib.rs";

    // println!("cargo::warning=genmc_path: {genmc_path:?}");
    // println!("cargo::warning=genmc_src_path: {genmc_src_path:?}");
    // println!("cargo::warning=cxx_bridge_include_path: {cxx_bridge_include_path:?}");

    let opt_level = 2;
    let debug_flags = "-D ENABLE_GENMC_DEBUG"; // FIXME(genmc): should this be enabled?

    // let debug_flags = "-D_GLIBCXX_DEBUG"; // TODO: this causes issue, code compiled with CXX is incompatible with other code
    let cpp_flags = Some(format!(
        "-O{opt_level} -g {debug_flags} -I {} -I {} -I {}",
        genmc_path.to_str().unwrap(),
        cxx_bridge_include_path.to_str().unwrap(),
        genmc_src_path.to_str().unwrap()
    ));
    let autotools_cpp_flags = cpp_flags.as_ref().map(|flags| format!("CXXFLAGS={flags}"));
    let autotools_c_flags = cpp_flags.map(|flags| format!("CFLAGS={flags}"));

    // HACK: GenMC uses autotools, this is a bit of a HACK to make this work (should be replaced at some point)
    // (This needs to run before building the bridge, since it creates some required header files)
    // std::env::set_current_dir("./genmc").unwrap();
    // println!("cargo::warning=New working directory': {:?}'", std::env::current_dir().unwrap());
    assert!(
        Command::new("autoreconf")
            .arg("--install")
            .current_dir(&genmc_path)
            .status()
            .expect("failed to run command")
            .success(),
        "autoreconf failed!"
    );
    // let args = [Some(format!("--with-llvm={LLVM_PATH}")), autotools_c_flags, autotools_cpp_flags].into_iter().flatten();
    let args = [autotools_c_flags, autotools_cpp_flags].into_iter().flatten();
    assert!(
        Command::new("./configure")
            .args(args)
            .current_dir(&genmc_path)
            .status()
            .expect("failed to run command")
            .success(),
        "./configure failed!"
    );

    cxx_build::bridge(RUST_CXX_BRIDGE_FILE_PATH)
        .compiler("g++") // TODO GENMC (BUILD): make sure GenMC uses the same compiler as the cxx_bridge
        .opt_level(opt_level)
        .debug(true)
        .warnings(false) // TODO GENMC (TESTING): try to fix some of those warnings
        .std("c++20")
        .flag("-fno-exceptions")
        .flag("-lffi")
        .flag("-ldl")
        .flag("-lLLVM-19")
        .flag(debug_flags) // TODO GENMC (TESTING): make this work somehow
        .include(&genmc_path)
        // .include("./genmc/include") // For GenMC tests, DO NOT INCLUDE!!
        .include(&genmc_src_path)
        .include(LLVM_PATH)
        .file(miri_genmc_interface_path)
        .compile("genmc_interop");

    assert!(
        Command::new("make")
            .arg(format!("-j{make_command_num_threads}"))
            .current_dir(&genmc_path)
            .status()
            .expect("failed to run command")
            .success(),
        "make failed!"
    );

    // Simply link the library without using pkg-config
    println!("cargo::rustc-link-search=native={}", genmc_path.to_str().unwrap());
    println!("cargo::rustc-link-search=native={LLVM_PATH}");
    println!("cargo::rustc-link-lib=static=genmc");
    println!("cargo::rustc-link-lib=static=genmc_interop");
    println!("cargo::rustc-link-lib=ffi");
    println!("cargo::rustc-link-lib=dl");
    println!("cargo::rustc-link-lib=dylib=LLVM-19");

    println!("cargo:rerun-if-changed={RUST_CXX_BRIDGE_FILE_PATH}");

    // We should rerun the makefile if any GenMC source file is changed
    let extensions = ["cpp", "cc", "hpp", "h", "c", "am"].map(os_str::OsStr::new);
    for entry in WalkDir::new(genmc_src_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| extensions.contains(&ext)) {
            println!("cargo::rerun-if-changed={}", path.display());
        }
    }
}
