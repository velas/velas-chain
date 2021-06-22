use solana_sdk::process_instruction::Logger;
use std::fmt::Write;
pub struct MultilineLogger<'a> {
    logger: &'a dyn Logger,
    line: String,
}
impl<'a> MultilineLogger<'a> {
    pub fn new(logger: &'a dyn Logger) -> Self {
        Self {
            logger,
            line: String::new(),
        }
    }
}

impl<'a> Write for MultilineLogger<'a> {
    fn write_str(&mut self, message: &str) -> std::fmt::Result {
        for c in message.chars() {
            if c == '\n' {
                self.logger.log(&*self.line);
                self.line.clear();
            }
            self.line.push(c);
        }
        Ok(())
    }
}

impl<'a> Drop for MultilineLogger<'a> {
    fn drop(&mut self) {
        self.logger.log(&*self.line);
    }
}
