use super::GenmcParams;

// TODO GENMC: document this:
#[derive(Debug, Default, Clone)]
pub struct GenmcConfig {
    pub(super) params: GenmcParams,
    print_graph: GenmcPrintGraphSetting,
}

// TODO GENMC: document this:
#[derive(Debug, Default, Clone, Copy)]
enum GenmcPrintGraphSetting {
    #[default]
    None,
    First,
    All,
}

impl Default for GenmcParams {
    fn default() -> Self {
        Self {
            memory_model: "RC11".into(),
            print_random_schedule_seed: false,
            disable_race_detection: false,
            quiet: true,
            log_level_trace: false,
            do_symmetry_reduction: false, // TODO GENMC (PERFORMANCE): maybe make this default `true`
        }
    }
}

impl GenmcConfig {
    fn set_graph_printing(&mut self, param: &str) {
        if !param.starts_with("=") {
            // TODO GENMC: find a good default here:
            self.print_graph = GenmcPrintGraphSetting::First;
            return;
        }
        // Remove the equals:
        let param = &param[1..];
        self.print_graph = match param {
            "none" | "false" | "" => GenmcPrintGraphSetting::None,
            "first" | "true" => GenmcPrintGraphSetting::First,
            // TODO GENMC: are these graphs always the same? Would printing the last one make more sense?
            "all" => GenmcPrintGraphSetting::All,
            _ => todo!("Unsupported argument"),
        }
    }

    fn set_log_level_trace(&mut self) {
        self.params.quiet = false;
        self.params.log_level_trace = true;
    }

    pub fn disable_data_race_detector(&mut self) {
        self.params.disable_race_detection = true;
    }

    /// Function for parsing command line options for GenMC mode.
    /// All GenMC arguments start with the string "-Zmiri-genmc".
    ///
    /// `trimmed_arg` should be the argument to be parsed, with the suffix "-Zmiri-genmc" removed
    pub fn parse_arg(genmc_config: &mut Option<GenmcConfig>, trimmed_arg: &str) {
        if genmc_config.is_none() {
            *genmc_config = Some(Default::default());
        }
        if trimmed_arg.is_empty() {
            return; // this corresponds to "-Zmiri-genmc"
        }
        let genmc_config = genmc_config.as_mut().unwrap();
        let trimmed_arg = trimmed_arg
            .strip_prefix("-")
            .unwrap_or_else(|| panic!("Invalid GenMC argument \"-Zmiri-genmc{trimmed_arg}\""));
        if trimmed_arg == "log-trace" {
            // TODO GENMC: maybe expand to allow more control over log level?
            genmc_config.set_log_level_trace();
        } else if let Some(param) = trimmed_arg.strip_prefix("print-graph") {
            // TODO GENMC (DOCUMENTATION)
            genmc_config.set_graph_printing(param);
        } else if trimmed_arg == "disable-race-detection" {
            // TODO GENMC (DOCUMENTATION)
            // genmc_config.params.disable_race_detection = true;
            todo!("GenMC: reuse Miri flag for disabling race detection, don't add a new one");
        } else if trimmed_arg == "symmetry-reduction" {
            // TODO GENMC (PERFORMANCE): maybe make this the default, have an option to turn it off instead
            genmc_config.params.do_symmetry_reduction = true;
        } else {
            // TODO GENMC: how to properly handle this?
            panic!("Invalid GenMC argument: \"-Zmiri-genmc-{trimmed_arg}\"");
        }
    }

    pub fn should_print_graph(&self, rep: usize) -> bool {
        matches!(
            (self.print_graph, rep),
            (GenmcPrintGraphSetting::First, 0) | (GenmcPrintGraphSetting::All, _)
        )
    }
}
