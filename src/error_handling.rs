//! Per-procedure VBA error-policy state transitions.
//!
//! This models the language policy transitions independently of CFG path
//! feasibility. It does not guess which statements can raise host/runtime errors.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnErrorMode {
    ResumeNext,
    GoToLabel(String),
    Disable,
    ClearActiveError,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResumeMode {
    RetryFault,
    NextStatement,
    GoToLabel(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorTransfer {
    ContinueAfterFault { fault: usize },
    TransferToHandler { label: String, fault: usize },
    PropagateToCaller { fault: usize },
    TerminateHost { fault: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResumeTransfer {
    Retry { fault: usize },
    ContinueAfterFault { fault: usize },
    GoToLabel { label: String, fault: usize },
    ResumeWithoutActiveError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Policy {
    Default,
    ResumeNext,
    GoTo(String),
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcedureErrorState {
    policy: Policy,
    active_fault: Option<usize>,
    handler_active: bool,
    directly_invoked_by_host: bool,
}

impl ProcedureErrorState {
    pub fn new(directly_invoked_by_host: bool) -> Self {
        Self {
            policy: Policy::Default,
            active_fault: None,
            handler_active: false,
            directly_invoked_by_host,
        }
    }

    /// Executing `On Error` resets `Err`; `GoTo 0` disables the current handler.
    pub fn configure(&mut self, mode: OnErrorMode) {
        match mode {
            OnErrorMode::ResumeNext => self.policy = Policy::ResumeNext,
            OnErrorMode::GoToLabel(label) => self.policy = Policy::GoTo(label),
            OnErrorMode::Disable => self.policy = Policy::Default,
            OnErrorMode::ClearActiveError => {
                self.active_fault = None;
                self.handler_active = false;
            }
            OnErrorMode::Unknown => self.policy = Policy::Unknown,
        }
        self.active_fault = None;
        self.handler_active = false;
    }

    /// Route one possible fault according to this activation's current policy.
    pub fn raise(&mut self, fault: usize) -> ErrorTransfer {
        if self.handler_active {
            return self.unhandled(fault);
        }
        match &self.policy {
            Policy::ResumeNext => ErrorTransfer::ContinueAfterFault { fault },
            Policy::GoTo(label) => {
                let label = label.clone();
                self.active_fault = Some(fault);
                self.handler_active = true;
                ErrorTransfer::TransferToHandler { label, fault }
            }
            Policy::Default | Policy::Unknown => self.unhandled(fault),
        }
    }

    /// A `Resume` is valid only while this activation is handling an active error.
    pub fn resume(&mut self, mode: ResumeMode) -> ResumeTransfer {
        let Some(fault) = self.active_fault else {
            return ResumeTransfer::ResumeWithoutActiveError;
        };
        self.active_fault = None;
        self.handler_active = false;
        match mode {
            ResumeMode::RetryFault => ResumeTransfer::Retry { fault },
            ResumeMode::NextStatement => ResumeTransfer::ContinueAfterFault { fault },
            ResumeMode::GoToLabel(label) => ResumeTransfer::GoToLabel { label, fault },
        }
    }

    pub fn handler_is_active(&self) -> bool {
        self.handler_active
    }

    fn unhandled(&self, fault: usize) -> ErrorTransfer {
        if self.directly_invoked_by_host {
            ErrorTransfer::TerminateHost { fault }
        } else {
            ErrorTransfer::PropagateToCaller { fault }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_resume_next_from_goto_handler_and_active_handler_failure() {
        let mut state = ProcedureErrorState::new(false);
        state.configure(OnErrorMode::ResumeNext);
        assert_eq!(
            state.raise(3),
            ErrorTransfer::ContinueAfterFault { fault: 3 }
        );

        state.configure(OnErrorMode::GoToLabel("Handler".into()));
        assert_eq!(
            state.raise(8),
            ErrorTransfer::TransferToHandler {
                label: "Handler".into(),
                fault: 8
            }
        );
        assert!(state.handler_is_active());
        assert_eq!(
            state.raise(9),
            ErrorTransfer::PropagateToCaller { fault: 9 }
        );
        assert_eq!(
            state.resume(ResumeMode::NextStatement),
            ResumeTransfer::ContinueAfterFault { fault: 8 }
        );
        assert!(!state.handler_is_active());
        assert_eq!(
            state.raise(10),
            ErrorTransfer::TransferToHandler {
                label: "Handler".into(),
                fault: 10
            }
        );
    }

    #[test]
    fn default_error_policy_depends_on_host_entry_and_go_to_zero_disables_handler() {
        let mut called = ProcedureErrorState::new(false);
        assert_eq!(
            called.raise(1),
            ErrorTransfer::PropagateToCaller { fault: 1 }
        );
        called.configure(OnErrorMode::GoToLabel("E".into()));
        let _ = called.raise(2);
        let _ = called.resume(ResumeMode::RetryFault);
        called.configure(OnErrorMode::Disable);
        assert_eq!(
            called.raise(3),
            ErrorTransfer::PropagateToCaller { fault: 3 }
        );

        let mut host = ProcedureErrorState::new(true);
        assert_eq!(host.raise(4), ErrorTransfer::TerminateHost { fault: 4 });
        assert_eq!(
            called.resume(ResumeMode::RetryFault),
            ResumeTransfer::ResumeWithoutActiveError
        );
    }
}
