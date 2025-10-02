use std::ops::Deref;

use quinn::Connection as QuinnConnection;

#[derive(Clone)]
pub struct QuicClient(QuinnConnection);
impl Deref for QuicClient {
    type Target = QuinnConnection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl From<QuinnConnection> for QuicClient {
    fn from(value: QuinnConnection) -> Self {
        Self(value)
    }
}
impl std::hash::Hash for QuicClient {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.stable_id().hash(state);
    }
}
impl PartialEq for QuicClient {
    fn eq(&self, other: &Self) -> bool {
        self.0.stable_id() == other.0.stable_id()
    }
}
impl Eq for QuicClient {}
