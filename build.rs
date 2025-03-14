use std::ffi::os_str;

use walkdir::WalkDir;

fn main() {
    // use autotools;
    // Build the project in the path `foo` and installs it in `$OUT_DIR`
    // let dst = autotools::build("genmc");
    // use autotools::Config;
    use std::process::Command;

    const GENMC_PATH: &str = "./genmc";
    const GENMC_MIRI_BUILD_PATH: &str = "./target/genmc_interop/";
    const LLVM_PATH: &str = "/usr/lib/llvm-19/lib";

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

    // TODO GENMC: pipe the output into the correct files (also enable changing 'target' dir)
    // assert!(Command::new("mkdir").arg(GENMC_MIRI_BUILD_PATH).status().expect("failed to run command").success(), "mkdir failed!");
    // assert!(Command::new("cxxbridge").arg("src/genmc/mod.rs").arg("--header").status().expect("failed to run command").success(), "cxxbridge failed!");
    // assert!(Command::new("cxxbridge").arg("src/genmc/mod.rs").status().expect("failed to run command").success(), "cxxbridge failed!");

    // println!("cargo::warning=Old working directory': {:?}'", std::env::current_dir().unwrap());
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
    assert!(
        Command::new("./configure").status().expect("failed to run command").success(),
        "./configure failed!"
    );
    assert!(
        Command::new("make").arg("-j").status().expect("failed to run command").success(),
        "make failed!"
    );
    std::env::set_current_dir("../").unwrap();

    cxx_build::bridge("src/genmc/mod.rs")
        .cpp(true)
        .warnings(false) // TODO GENMC: try to fix some of those warnings
        .std("c++20")
        .include("./genmc")
        // .include("./genmc/include") // For GenMC tests, DO NOT INCLUDE!!
        .include("./genmc/src")
        .include(LLVM_PATH)
        .flag("-lffi")
        .flag("-ldl")
        .flag("-lLLVM-19")
        .file("./genmc/src/Verification/MiriInterface.hpp")
        .compile("genmc_interop");

    // Simply link the library without using pkg-config
    // println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo::rustc-link-search=native={GENMC_PATH}");
    println!("cargo::rustc-link-search=native={GENMC_MIRI_BUILD_PATH}");
    println!("cargo::rustc-link-search=native={LLVM_PATH}");
    // println!("cargo::rustc-link-lib=static=bridge.cc");
    println!("cargo::rustc-link-lib=static=genmc");
    println!("cargo::rustc-link-lib=static=genmc_interop");
    println!("cargo::rustc-link-lib=ffi");
    println!("cargo::rustc-link-lib=dl");
    println!("cargo::rustc-link-lib=dylib=LLVM-19");

    println!("cargo:rerun-if-changed=src/genmc/mod.rs");
    // println!("cargo:rerun-if-changed=src/");
    // println!("cargo:rerun-if-changed=genmc/src/Verification/MiriInterface.hpp");
    // Recursively walk the directory

    let extensions = ["cpp", "cc", "hpp", "h", "c", "am"].map(os_str::OsStr::new);
    for entry in WalkDir::new(GENMC_PATH).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| extensions.contains(&ext)) {
            println!("cargo::rerun-if-changed={}", path.display());
        }
    }
}
