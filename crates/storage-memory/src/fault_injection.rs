use parking_lot::Mutex;
use soland_storage::{PersistenceError, PersistenceResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    EventCommit,
    WebvhLogCommit,
    AgentPut,
    IdempotencyRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultTiming {
    Before,
    After,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultPlan {
    pub point: FaultPoint,
    pub timing: FaultTiming,
    pub occurrence: usize,
}

impl FaultPlan {
    pub fn new(point: FaultPoint, timing: FaultTiming, occurrence: usize) -> Self {
        assert!(occurrence > 0, "fault occurrence must be positive");
        Self {
            point,
            timing,
            occurrence,
        }
    }
}

#[derive(Debug)]
struct ArmedFault {
    plan: FaultPlan,
    observed: usize,
}

#[derive(Debug, Default)]
pub struct FaultInjector {
    armed: Mutex<Option<ArmedFault>>,
}

impl FaultInjector {
    pub fn arm(&self, plan: FaultPlan) {
        *self.armed.lock() = Some(ArmedFault { plan, observed: 0 });
    }

    pub fn clear(&self) {
        self.armed.lock().take();
    }

    pub(crate) fn check(&self, point: FaultPoint, timing: FaultTiming) -> PersistenceResult<()> {
        let mut armed = self.armed.lock();
        let Some(fault) = armed.as_mut() else {
            return Ok(());
        };
        if fault.plan.point != point || fault.plan.timing != timing {
            return Ok(());
        }
        fault.observed += 1;
        if fault.observed != fault.plan.occurrence {
            return Ok(());
        }
        armed.take();
        Err(PersistenceError::Database(format!(
            "injected {timing:?} failure at {point:?}"
        )))
    }
}
