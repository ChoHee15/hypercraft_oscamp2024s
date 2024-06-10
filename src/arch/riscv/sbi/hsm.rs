use sbi_spec::hsm::{HART_START, HART_STOP, HART_GET_STATUS, HART_SUSPEND};

use crate::HyperResult;

#[derive(Clone, Copy, Debug)]
pub enum HSMFunction {
    HART_START{
        hartid: usize,
        start_addr: usize,
        opaque: usize
    },
    HART_STOP,
    HART_GET_STATUS{
        hartid: usize,
    },
    HART_SUSPEND{
        suspend_type: usize,
        resume_addr: usize,
        opaque: usize,
    }
}

impl HSMFunction {
    pub fn from_args(args: &[usize]) -> HyperResult<Self> {
        match args[6] {
            HART_START => Ok(Self::HART_START{
                hartid: args[0] as usize,
                start_addr: args[1] as usize,
                opaque: args[2] as usize,
            }),
            HART_STOP => Ok(Self::HART_STOP),
            HART_GET_STATUS => Ok(Self::HART_GET_STATUS{
                hartid: args[0] as usize,
            }),
            HART_SUSPEND => Ok(Self::HART_SUSPEND{
                suspend_type: args[0] as usize,
                resume_addr: args[1] as usize,
                opaque: args[2] as usize,
            }),
            _ => panic!("Unsupported yet!"),
        }
    }
}
