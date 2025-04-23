#[cfg(feature = "genmc")]
use std::ffi::os_str;
#[cfg(feature = "genmc")]
use std::process::Command;

#[cfg(feature = "genmc")]
use walkdir::WalkDir;

#[cfg(not(feature = "genmc"))]
fn main() {
    println!("cargo:rerun-if-changed=src/genmc/build.rs");
}

#[cfg(feature = "genmc")]
fn main() {
    // Build the project in the path `foo` and installs it in `$OUT_DIR`
    // let dst = autotools::build("genmc");

    const GENMC_PATH: &str = "./genmc";
    const LLVM_PATH: &str = "/usr/lib/llvm-19/lib";

    const CXX_BRIDGE_INCLUDE_PATH: &str = "/root/miri/target/cxxbridge";
    const WORKSPACE_INCLUDE_PATH: &str = "/root/";

    // cxx_build::CFG.include_prefix = "";

    // let dst = Config::new("./genmc")
    //     .reconf("--install")
    //     // .configure()
    //     // .reconf("-ivf")
    //     // .enable("feature", None)
    //     // .with("dep", None)
    //     // .disable("otherfeature", None)
    //     // .without("otherdep", None)
    //     // .cflag("-Wall")
    //     // .cflag("Wextra")
    //     .build();

    // let cpp_flags = None;

    // let opt_level = 0;
    let opt_level = 2;

    let debug_flags = "-D ENABLE_GENMC_DEBUG";
    // let debug_flags = "-D_GLIBCXX_DEBUG"; // TODO: this causes issue, code compiled with CXX is incompatible with other code
    let cpp_flags = Some(format!(
        "-O{opt_level} -g {debug_flags} -I {WORKSPACE_INCLUDE_PATH} -I {CXX_BRIDGE_INCLUDE_PATH}"
    ));
    let autotools_cpp_flags = cpp_flags.clone().map(|flags| format!("CXXFLAGS={flags}"));
    let autotools_c_flags = cpp_flags.map(|flags| format!("CFLAGS={flags}"));

    // HACK: GenMC uses autotools, this is a bit of a HACK to make this work (should be replaced at some point)
    // (This needs to run before building the bridge, since it creates some required header files)
    std::env::set_current_dir("./genmc").unwrap();
    println!("cargo::warning=New working directory': {:?}'", std::env::current_dir().unwrap());
    assert!(
        Command::new("autoreconf")
            .arg("--install")
            .status()
            .expect("failed to run command")
            .success(),
        "autoreconf failed!"
    );
    let args = [autotools_c_flags, autotools_cpp_flags].into_iter().flatten();
    assert!(
        Command::new("./configure").args(args).status().expect("failed to run command").success(),
        "./configure failed!"
    );
    std::env::set_current_dir("../").unwrap();

    cxx_build::bridge("src/genmc/mod.rs")
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
        .include("./genmc")
        // .include("./genmc/include") // For GenMC tests, DO NOT INCLUDE!!
        .include("./genmc/src")
        .include(LLVM_PATH)
        .file("./genmc/src/Verification/MiriInterface.hpp")
        .compile("genmc_interop");

    // another HACK: we `make` GenMC (after the CXX bridge since it depends on it)
    // println!("cargo::warning=Old working directory': {:?}'", std::env::current_dir().unwrap());
    std::env::set_current_dir("./genmc").unwrap();
    println!("cargo::warning=New working directory': {:?}'", std::env::current_dir().unwrap());

    assert!(
        Command::new("make").arg("-j8").status().expect("failed to run command").success(),
        "make failed!"
    );
    std::env::set_current_dir("../").unwrap();

    // Simply link the library without using pkg-config
    println!("cargo::rustc-link-search=native={GENMC_PATH}");
    println!("cargo::rustc-link-search=native={LLVM_PATH}");
    println!("cargo::rustc-link-lib=static=genmc");
    println!("cargo::rustc-link-lib=static=genmc_interop");
    println!("cargo::rustc-link-lib=ffi");
    println!("cargo::rustc-link-lib=dl");
    println!("cargo::rustc-link-lib=dylib=LLVM-19");

    println!("cargo:rerun-if-changed=src/genmc/mod.rs");

    // Recursively walk the directory
    let extensions = ["cpp", "cc", "hpp", "h", "c", "am"].map(os_str::OsStr::new);
    for entry in WalkDir::new(GENMC_PATH).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| extensions.contains(&ext)) {
            println!("cargo::rerun-if-changed={}", path.display());
        }
    }
}
