#[cfg(not(feature = "genmc"))]
fn main() {
    println!("cargo:rerun-if-changed=src/genmc/build.rs");
}

#[cfg(feature = "genmc")]
fn main() {
    use std::ffi::os_str;
    use std::process::Command;

    use walkdir::WalkDir;

    // Build the project in the path `foo` and installs it in `$OUT_DIR`
    // let dst = autotools::build("genmc");

    let make_command_num_threads = num_cpus::get();

    const GENMC_PATH: &str = "./genmc";
    const LLVM_PATH: &str = "/usr/lib/llvm-19/lib";

    let mut workspace_include_path = std::env::current_dir().unwrap(); // TODO GENMC: is this still required?
    workspace_include_path.pop();
    let mut cxx_bridge_include_path = std::env::current_dir().unwrap();
    cxx_bridge_include_path.push("target");
    cxx_bridge_include_path.push("cxxbridge");

    /// Rust source file containing the #[cxx::bridge] code for GenMC interop.
    const GENMC_SOURCE_FILE: &str = "src/concurrency/genmc/cxx_interface.rs";

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

    let opt_level = 2;

    let debug_flags = "-D ENABLE_GENMC_DEBUG";
    // let debug_flags = "-D_GLIBCXX_DEBUG"; // TODO: this causes issue, code compiled with CXX is incompatible with other code
    let cpp_flags = Some(format!(
        "-O{opt_level} -g {debug_flags} -I {} -I {}",
        workspace_include_path.to_str().unwrap(),
        cxx_bridge_include_path.to_str().unwrap()
    ));
    let autotools_cpp_flags = cpp_flags.as_ref().map(|flags| format!("CXXFLAGS={flags}"));
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
    // let args = [Some(format!("--with-llvm={LLVM_PATH}")), autotools_c_flags, autotools_cpp_flags].into_iter().flatten();
    let args = [autotools_c_flags, autotools_cpp_flags].into_iter().flatten();
    assert!(
        Command::new("./configure").args(args).status().expect("failed to run command").success(),
        "./configure failed!"
    );
    std::env::set_current_dir("../").unwrap();

    cxx_build::bridge(GENMC_SOURCE_FILE)
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
        Command::new("make").arg(format!("-j{make_command_num_threads}")).status().expect("failed to run command").success(),
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

    println!("cargo:rerun-if-changed={GENMC_SOURCE_FILE}");

    // We should rerun the makefile if any GenMC files is changed
    let extensions = ["cpp", "cc", "hpp", "h", "c", "am"].map(os_str::OsStr::new);
    for entry in WalkDir::new(GENMC_PATH).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| extensions.contains(&ext)) {
            println!("cargo::rerun-if-changed={}", path.display());
        }
    }
}
