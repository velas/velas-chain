use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub struct TmpDir(PathBuf);

impl TmpDir {
    pub fn new<P: AsRef<Path>>(sub_dir: P) -> Self {
        let path = env::temp_dir().join(sub_dir);
        let pprint = path.as_path().display();
        if path.exists() {
            panic!("Path is {} already exists", pprint);
        }
        fs::create_dir(&path)
            .unwrap_or_else(|err| panic!("Unable to create tmp dir {}: {:?}", pprint, err));
        println!("{}", pprint);
        Self(path)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        fs::remove_dir_all(self.0.as_path()).unwrap_or_else(|err| {
            panic!(
                "Unable to remove tmp dir {}: {:?}",
                self.0.as_path().display(),
                err
            )
        });
    }
}

impl AsRef<Path> for TmpDir {
    fn as_ref(&self) -> &Path {
        self.0.as_path()
    }
}
