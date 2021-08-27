pub mod init;
pub mod versions;

use console::{style, Emoji};
use indicatif::{ProgressBar, ProgressStyle};

static TRUCK: Emoji = Emoji("🚚 ", "");
static LOOKING_GLASS: Emoji = Emoji("🔍 ", "");
static BULLET: Emoji = Emoji("• ", "* ");
static SPARKLE: Emoji = Emoji("✨ ", "");
static PACKAGE: Emoji = Emoji("📦 ", "");
static RECYCLING: Emoji = Emoji("♻️ ", "");

/// Pretty print a "name value"
fn println_name_value(name: &str, value: &str) {
    println!("{} {}", style(name).bold(), value);
}

/// Creates a new process bar for processing that will take an unknown amount of time
fn new_spinner_progress_bar() -> ProgressBar {
    let progress_bar = ProgressBar::new(42);
    progress_bar
        .set_style(ProgressStyle::default_spinner().template("{spinner:.green} {wide_msg}"));
    progress_bar.enable_steady_tick(100);
    progress_bar
}
