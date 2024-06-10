use sbi_spec::spi::SEND_IPI;

use crate::HyperResult;

#[derive(Clone, Copy, Debug)]

pub enum IPIFunction {
    SEND_IPI {
        hart_mask: usize,
        hart_mask_base: usize,
    },
}

impl IPIFunction {
    pub fn from_args(args: &[usize]) -> HyperResult<Self> {
        match args[6] {
            SEND_IPI => Ok(Self::SEND_IPI{
                hart_mask: args[0] as usize,
                hart_mask_base: args[1] as usize,
            }),
            _ => panic!("Unsupported yet!"),
        }
    }
}
