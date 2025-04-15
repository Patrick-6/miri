use super::GenmcParams;

// TODO GENMC: document this:
#[derive(Debug, Default, Clone)]
pub struct GenmcConfig {
    pub params: GenmcParams,
    pub print_graph: GenmcPrintGraphSetting,
}

// TODO GENMC: document this:
#[derive(Debug, Default, Clone, Copy)]
pub enum GenmcPrintGraphSetting {
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
        }
    }
}

impl GenmcConfig {
    pub fn set_graph_printing(&mut self, param: &str) {
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

    pub fn set_log_level_trace(&mut self) {
        self.params.quiet = false;
        self.params.log_level_trace = true;
    }
}
