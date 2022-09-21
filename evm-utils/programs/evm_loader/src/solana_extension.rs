use solana_program_runtime::{ic_logger_msg, log_collector::LogCollector};
use std::cell::RefCell;
use std::fmt::Write;
use std::rc::Rc;
pub struct MultilineLogger {
    logger: Option<Rc<RefCell<LogCollector>>>,
    line: String,
}
impl MultilineLogger {
    pub fn new(logger: Option<Rc<RefCell<LogCollector>>>) -> Self {
        Self {
            logger,
            line: String::new(),
        }
    }
}

impl Write for MultilineLogger {
    fn write_str(&mut self, message: &str) -> std::fmt::Result {
        for c in message.chars() {
            if c == '\n' {
                ic_logger_msg!(self.logger, &self.line);
                self.line.clear();
            }
            self.line.push(c);
        }
        Ok(())
    }
}

impl Drop for MultilineLogger {
    fn drop(&mut self) {
        ic_logger_msg!(self.logger, &self.line);
    }
}
