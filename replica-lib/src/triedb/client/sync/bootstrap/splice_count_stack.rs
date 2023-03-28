// one - SpliceCountStack<Vec<(H256, bool)>>
// two - SpliceCountStack<Result<Vec<((H256, bool), Vec<u8>)>>>
pub struct SpliceCountStack<S> {
    tag: String,
    inner: Vec<S>,
    count: Option<usize>,
}

pub trait Length {
    fn length(&self) -> Option<usize>;
}

impl<E> Length for Vec<E> {
    fn length(&self) -> Option<usize> {
        Some(self.len())
    }
}

impl<E, ERR> Length for Result<Vec<E>, ERR> {
    fn length(&self) -> Option<usize> {
        match self {
            Ok(vecy) => Some(vecy.len()),
            Err(..) => None,
        }
    }
}

impl<S> SpliceCountStack<S> {
    pub fn new(tag: String) -> Self {
        Self {
            inner: Vec::new(),
            count: Some(0),
            tag,
        }
    }
}

impl<S: Length> SpliceCountStack<S> {
    pub fn push(&mut self, chunk: S) {
        if let Some(length) = chunk.length() {
            if length == 0 {
                panic!("cannot push empty chunks, no use");
            }
            if let Some(count) = self.count {
                self.count = Some(count + length);
            }
        } else {
            self.count = None;
        }
        self.inner.push(chunk);
        log::debug!(
            "(after push) current total \"{}\": {:?}",
            self.tag,
            self.count
        );
    }
    pub fn pop(&mut self) -> Option<S> {
        let ret = self.inner.pop();
        if let Some(ref chunk) = ret {
            if let Some(length) = chunk.length() {
                if let Some(count) = self.count {
                    self.count = Some(count - length);
                }
            } else {
                self.count = None;
            }
        }
        log::debug!(
            "(after pop)  current total \"{}\": {:?}",
            self.tag,
            self.count
        );
        ret
    }
}
