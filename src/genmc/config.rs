use crate::MiriConfig;

#[derive(Debug, Default, Clone)]
pub struct GenmcConfig {
    // TODO: add fields
}

impl Default for GenmcParams {
    fn default() -> Self {
        todo!()
    }
}

impl GenmcConfig {
    /// Function for parsing command line options for GenMC mode.
    /// All GenMC arguments start with the string "-Zmiri-genmc".
    /// 
    /// `trimmed_arg` should be the argument to be parsed, with the suffix "-Zmiri-genmc" removed
    pub fn parse_arg(miri_config: &mut MiriConfig, trimmed_arg: &str) {
        if miri_config.genmc_config.is_none() {
            miri_config.genmc_config = Some(Default::default());

            // FIXME: make sure none of the following settings are reactivated by other passed arguments:

            // GenMC handles data race detection and weak memory emulation, so we disable the Miri equivalents:
            miri_config.data_race_detector = false;
            miri_config.weak_memory_emulation = false;
            // FIXME: Currently GenMC mode incompatible with aliasing model checking
            miri_config.borrow_tracker = None;

            todo!("GenMC mode not yet supported")
        }
        todo!("implement parsing of GenMC options")
    }
    
    pub fn should_print_graph(&self, rep: usize) -> bool {
        match (self.print_graph, rep) {
            (GenmcPrintGraphSetting::First, 0) | (GenmcPrintGraphSetting::All, _) => true,
            _ => false,
        }
    }
}
