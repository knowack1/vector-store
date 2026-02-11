use scylla::value::CqlValue;
use std::hash::Hash;
use std::hash::Hasher;

#[derive(Clone, Debug, derive_more::From)]
pub struct PrimaryKey(pub(crate) Vec<CqlValue>);

impl Hash for PrimaryKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        format!("{self:?}").hash(state);
    }
}

impl PartialEq for PrimaryKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Eq for PrimaryKey {}
