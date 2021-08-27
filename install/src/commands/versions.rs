use chrono::prelude::*;
use console::style;

use super::*;

use crate::github::GithubReleases;

static COL_WIDTH_VERSION: usize = 15;
static COL_WIDTH_DESCR: usize = 41;
static COL_WIDTH_CHANNEL: usize = 9;
static COL_WIDTH_PUBLISHED: usize = 18;

// hack needed to correctly fit styled string with unprintable chars to ascii-table
static FORMATTED_DELTA: usize = 8;

pub fn command_versions() -> Result<(), String> {
    let release_db = GithubReleases::load_from_github()
        .map_err(|e| format!("Unable to fetch release list: {:?}", e))?;

    println_name_value(&format!(" {}versions available for download:", BULLET), "");

    print!("┌");
    (0..COL_WIDTH_VERSION).for_each(|_| print!("─"));
    print!("┬");
    (0..COL_WIDTH_DESCR).for_each(|_| print!("─"));
    print!("┬");
    (0..COL_WIDTH_CHANNEL).for_each(|_| print!("─"));
    print!("┬");
    (0..COL_WIDTH_PUBLISHED).for_each(|_| print!("─"));
    println!("┐");

    println!(
        "│ {0:<1$}│ {2:<3$}│ {4:<5$}│ {6:<7$}│",
        "VERSION",
        COL_WIDTH_VERSION - 1,
        "DESCRIPTION",
        COL_WIDTH_DESCR - 1,
        "CHANNEL",
        COL_WIDTH_CHANNEL - 1,
        "PUBLISHED",
        COL_WIDTH_PUBLISHED - 1
    );

    print!("├");
    (0..COL_WIDTH_VERSION).for_each(|_| print!("─"));
    print!("┼");
    (0..COL_WIDTH_DESCR).for_each(|_| print!("─"));
    print!("┼");
    (0..COL_WIDTH_CHANNEL).for_each(|_| print!("─"));
    print!("┼");
    (0..COL_WIDTH_PUBLISHED).for_each(|_| print!("─"));
    println!("┤");

    for release in release_db.all_versions() {
        let (description, delta) = match &release.description {
            Some(friendly_name) => (friendly_name.clone(), 0),
            None => (
                style("<unnamed release>").italic().to_string(),
                FORMATTED_DELTA,
            ),
        };

        let local_time: DateTime<Local> = DateTime::from(release.published_at);

        println!(
            "│ {version: <version_len$}│ {description: <description_len$}│ {channel: <channel_len$}│ {published: <published_len$}│",
            version = style(&release.semver.to_string()).bold().to_string(),
            version_len = COL_WIDTH_VERSION - 1 + FORMATTED_DELTA,
            description = description,
            description_len = COL_WIDTH_DESCR - 1 + delta,
            channel = release.channel,
            channel_len = COL_WIDTH_CHANNEL - 1,
            published = local_time.format("%F %R").to_string(),
            published_len = COL_WIDTH_PUBLISHED - 1
        );
    }

    print!("└");
    (0..COL_WIDTH_VERSION).for_each(|_| print!("─"));
    print!("┴");
    (0..COL_WIDTH_DESCR).for_each(|_| print!("─"));
    print!("┴");
    (0..COL_WIDTH_CHANNEL).for_each(|_| print!("─"));
    print!("┴");
    (0..COL_WIDTH_PUBLISHED).for_each(|_| print!("─"));
    println!("┘");

    Ok(())
}
