use std::path::PathBuf;

fn main() {
    /*
       Future TODOs:
       - Add automatic git checkout with specific commit
         - Add way to override this locally for development (e.g., if ./genmc exists, use that, otherwise, download specific commit from Github)
       - Get rid of LLVM dependency
       - Pass debug / release mode config to cmake
         - Decide if GENMC_DEBUG should stay enabled (or some subset of it?)

       Far Future TODOs:
       - Add cross language LTO
    */

    const GENMC_MIRI_LIB: &str = "genmc_miri";
    const RUST_CXX_BRIDGE_FILE_PATH: &str = "src/lib.rs";

    const LLVM_PATH: &str = "/usr/lib/llvm-19/lib"; // FIXME

    let genmc_path = PathBuf::from("../genmc/");
    let mut cmakelists_path = genmc_path.clone();
    cmakelists_path.push("CMakeLists.txt");

    let mut genmc_src_path = genmc_path.clone();
    genmc_src_path.push("src");

    let mut config = cmake::Config::new(cmakelists_path);
    config.profile("RelWithDebInfo"); // FIXME(genmc,cmake)
    config.define("GENMC_DEBUG", "ON");
    config.define("BUILD_DOC", "OFF"); // We don't need to build GenMC documentation here
    config.define("MIRI", "ON"); // FIXME(genmc,cmake): is this the proper way to do Miri-specific settings?
    config.define("LLI", "OFF");

    // // TODO GENMC(BUILD): attempt at running LTO:
    // // -DCMAKE_CXX_COMPILER=clang++
    // config.define("CMAKE_CXX_COMPILER", "clang++");
    // config.define("CMAKE_CXX_FLAGS", "-flto=thin");

    let dst = config.build();
    println!("cargo::warning=config.build() returned value: '{dst:?}'");
    // target/debug/build/genmc-sys-29018f8e78734f22/out/build/src/MiriInterop/libgenmc_miri.a
    // println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-search=native={}/build/src/MiriInterop/", dst.display());
    println!("cargo:rustc-link-lib=static={GENMC_MIRI_LIB}");

    println!("cargo::rustc-link-search=native={LLVM_PATH}"); // FIXME
    println!("cargo:rustc-link-lib=dylib=LLVM-19");

    // Only rebuild if we have to: FIXME(genmc,cmake): is there a better way to do this?
    println!("cargo:rerun-if-changed={RUST_CXX_BRIDGE_FILE_PATH}");

    // We should rerun the makefile if any GenMC source file is changed
    let extensions = ["cpp", "cc", "hpp", "h", "c"].map(std::ffi::os_str::OsStr::new);
    for entry in walkdir::WalkDir::new(genmc_src_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            if path.extension().is_some_and(|ext| extensions.contains(&ext))
                || entry.file_name().to_string_lossy().contains("CMakeLists.txt")
            {
                println!("cargo::rerun-if-changed={}", path.display());
            }
        }
    }
}
