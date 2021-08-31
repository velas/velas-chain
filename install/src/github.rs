use chrono::{DateTime, FixedOffset};
use serde_json::Value as JSValue;

#[derive(Debug)]
pub enum Version {
    LatestStable,
    LatestEdge,
    Semver(String),
}

#[derive(Debug)]
pub struct GithubRelease {
    /// Raw GitHub release tag
    pub tag_name: String,
    /// Human-friendly name of github release
    pub description: Option<String>,
    /// Parsed `semver` of GitHub release tag
    pub semver: semver::Version,
    /// Stable or edge release channel
    pub channel: String,
    /// Time of publish
    pub published_at: DateTime<FixedOffset>,
}

impl GithubRelease {
    pub fn download_url(&self, target: &str) -> String {
        format!(
            "https://github.com/velas/velas-chain/releases/download/{}/velas-release-{}.tar.bz2",
            self.tag_name, target
        )
    }
}

#[derive(Debug)]
pub struct GithubReleases {
    releases: Vec<GithubRelease>,
}

impl GithubReleases {
    pub fn load_from_github() -> reqwest::Result<Self> {
        let github_releases = reqwest::Url::parse(crate::defaults::GITHUB_RELEASES_URL).unwrap();

        let client = reqwest::blocking::Client::builder()
            .user_agent("velas-install")
            .build()?;

        let request = client
            .get(github_releases)
            .header("accept", "application/vnd.github.v3+json")
            .build()?;

        let response = client.execute(request)?;

        let releases: Vec<JSValue> = response.json()?;

        Ok(Self::from_api_entries(releases))
    }

    /// Converts and sorts raw GitHub DTOs with release metadata. DTOs with not semver-like
    /// tags (or semver-like tags with leading `v` char) omitted silently
    fn from_api_entries(api_entries: Vec<JSValue>) -> Self {
        let mut releases: Vec<_> = api_entries
            .into_iter()
            .filter_map(|release| {
                let tag_name = release["tag_name"].as_str().unwrap().to_string();
                let description = release["name"].as_str().map(String::from);
                let published_at = release["published_at"]
                    .as_str()
                    .map(DateTime::parse_from_rfc3339)
                    .unwrap()
                    .unwrap();
                Self::semver_of(&tag_name).map(|semver| {
                    let channel = if semver.pre.is_empty() {
                        "stable".to_string()
                    } else {
                        "edge".to_string()
                    };

                    GithubRelease {
                        tag_name,
                        description,
                        semver,
                        channel,
                        published_at,
                    }
                })
            })
            .collect();

        // most recent semver first
        releases.sort_by(|a, b| b.semver.cmp(&a.semver));

        Self { releases }
    }

    pub fn find_version(&self, version: &Version) -> Option<&GithubRelease> {
        match version {
            Version::LatestStable => self
                .releases
                .iter()
                .find(|release| release.semver.pre.is_empty()),
            Version::LatestEdge => self.releases.get(0),
            Version::Semver(version_req) => {
                semver::VersionReq::parse(version_req)
                    .ok()
                    .and_then(|version| {
                        self.releases
                            .iter()
                            .find(|release| version.matches(&release.semver))
                    })
            }
        }
    }

    pub fn all_versions(&self) -> impl Iterator<Item = &GithubRelease> {
        self.releases.iter()
    }

    /// Drops leading `v` char if present, and tries to parse tag into `semver::Version`
    fn semver_of(git_tag: &str) -> Option<semver::Version> {
        let semver_tag = if git_tag.starts_with('v') {
            git_tag.split_at(1).1
        } else {
            git_tag
        };

        semver::Version::parse(semver_tag).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_release_query() {
        let github_releases = include_str!("../tests_data/github_releases.json");

        let release_db =
            GithubReleases::from_api_entries(serde_json::from_str(github_releases).unwrap());

        // (test_query, expected_github_tag)
        let test_asserts_channels = [
            (Version::LatestEdge, "v2.0.0-alpha"),
            (Version::LatestStable, "v1.3.0"),
        ];

        for (test_query, expected_github_tag) in test_asserts_channels {
            assert_eq!(
                release_db.find_version(&test_query).unwrap().tag_name,
                expected_github_tag
            );
        }

        let test_asserts_semvers = [
            ("0.3.0", "v0.3.1"),
            ("1.1.0", "v1.3.0"),
            ("^1.1.0", "v1.3.0"),
            ("=1.1.0", "v1.1.0"),
            (">=1.1.0, <1.3.0", "v1.2.0"),
        ];

        for (test_query, expected_github_tag) in test_asserts_semvers {
            assert_eq!(
                release_db
                    .find_version(&Version::Semver(String::from(test_query)))
                    .unwrap()
                    .tag_name,
                expected_github_tag
            );
        }
    }

    #[test]
    fn test_release_list() {
        let github_releases = include_str!("../tests_data/github_releases.json");

        let release_db =
            GithubReleases::from_api_entries(serde_json::from_str(github_releases).unwrap());

        let versions: Vec<&GithubRelease> = release_db.all_versions().collect();

        assert_eq!(
            versions[0].description,
            Some("Release name here".to_string())
        );
        assert_eq!(versions[1].description, Some("".to_string()));
        assert_eq!(versions[2].description, None);
    }
}
