use std::rc::Rc;

use super::data_race;
use crate::{GenmcCtx, VisitProvenance, VisitWith};

pub enum ConcurrencyHandler {
    None,
    DataRace(Box<data_race::GlobalState>),
    GenMC(Rc<GenmcCtx>),
}

impl ConcurrencyHandler {
    pub fn is_none(&self) -> bool {
        matches!(self, ConcurrencyHandler::None)
    }

    pub fn as_data_race_ref(&self) -> Option<&data_race::GlobalState> {
        if let Self::DataRace(data_race) = self { Some(data_race) } else { None }
    }

    pub fn as_data_race_mut(&mut self) -> Option<&mut data_race::GlobalState> {
        if let Self::DataRace(data_race) = self { Some(data_race) } else { None }
    }

    pub fn as_genmc_ref(&self) -> Option<&GenmcCtx> {
        if let Self::GenMC(genmc_ctx) = self { Some(genmc_ctx) } else { None }
    }

    pub fn set_ongoing_action_data_race_free(&self, enable: bool) {
        match self {
            ConcurrencyHandler::None => {}
            ConcurrencyHandler::DataRace(data_race) => {
                data_race.set_ongoing_action_data_race_free(enable);
            }
            ConcurrencyHandler::GenMC(genmc_ctx) => {
                genmc_ctx.set_ongoing_action_data_race_free(enable);
            }
        }
    }
}

impl VisitProvenance for ConcurrencyHandler {
    fn visit_provenance(&self, visit: &mut VisitWith<'_>) {
        match self {
            ConcurrencyHandler::None => {}
            ConcurrencyHandler::DataRace(data_race) => data_race.visit_provenance(visit),
            ConcurrencyHandler::GenMC(genmc_ctx) => genmc_ctx.visit_provenance(visit),
        }
    }
}
