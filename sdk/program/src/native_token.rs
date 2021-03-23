/// There are 10^9 lamports in one VLX
pub const LAMPORTS_PER_VLX: u64 = 1_000_000_000;

/// Approximately convert fractional native tokens (lamports) into native tokens (VLX)
pub fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / LAMPORTS_PER_VLX as f64
}

/// Approximately convert native tokens (VLX) into fractional native tokens (lamports)
pub fn sol_to_lamports(sol: f64) -> u64 {
    (sol * LAMPORTS_PER_VLX as f64) as u64
}

pub const fn sol_to_lamports_u64(sol: u64) -> u64 {
    sol * LAMPORTS_PER_VLX
}

use std::fmt::{Debug, Display, Formatter, Result};
pub struct Sol(pub u64);

impl Sol {
    fn write_in_sol(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "◎{}.{:09}",
            self.0 / LAMPORTS_PER_VLX,
            self.0 % LAMPORTS_PER_VLX
        )
    }
}

impl Display for Sol {
    fn fmt(&self, f: &mut Formatter) -> Result {
        self.write_in_sol(f)
    }
}

impl Debug for Sol {
    fn fmt(&self, f: &mut Formatter) -> Result {
        self.write_in_sol(f)
    }
}
