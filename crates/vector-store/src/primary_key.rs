use scylla::value::CqlDate;
use scylla::value::CqlTime;
use scylla::value::CqlTimestamp;
use scylla::value::CqlTimeuuid;
use scylla::value::CqlValue;
use scylla::value::Counter;
use std::fmt;
use std::hash::Hash;
use std::hash::Hasher;
use std::net::IpAddr;
use uuid::Uuid;

/// A memory-compact CQL value for use in primary keys.
///
/// [`CqlValue`] is 72 bytes because its largest variant (`UserDefinedType`)
/// stores three heap-allocated fields inline, wasting ~68 bytes for a typical
/// `Int(i32)`.
///
/// `CompactCqlValue` keeps variants whose data is ≤ 8 bytes inline and boxes
/// larger payloads, bringing the enum size down to 24 bytes (3× smaller).
/// Only scalar CQL types valid for primary key columns are included.
#[derive(Clone)]
pub(crate) enum CompactCqlValue {
    // ── Inline variants (data ≤ 8 bytes) ────────────────────────────────
    Empty,
    Boolean(bool),
    TinyInt(i8),
    SmallInt(i16),
    Int(i32),
    Float(f32),
    Date(CqlDate),
    BigInt(i64),
    Double(f64),
    Counter(Counter),
    Time(CqlTime),
    Timestamp(CqlTimestamp),

    // ── Boxed variants (data > 8 bytes) ─────────────────────────────────
    Text(Box<String>),
    Ascii(Box<String>),
    Blob(Box<Vec<u8>>),
    Uuid(Box<Uuid>),
    Timeuuid(Box<CqlTimeuuid>),
    Inet(Box<IpAddr>),
}

impl From<CqlValue> for CompactCqlValue {
    fn from(v: CqlValue) -> Self {
        match v {
            CqlValue::Empty => Self::Empty,
            CqlValue::Boolean(v) => Self::Boolean(v),
            CqlValue::TinyInt(v) => Self::TinyInt(v),
            CqlValue::SmallInt(v) => Self::SmallInt(v),
            CqlValue::Int(v) => Self::Int(v),
            CqlValue::Float(v) => Self::Float(v),
            CqlValue::Date(v) => Self::Date(v),
            CqlValue::BigInt(v) => Self::BigInt(v),
            CqlValue::Double(v) => Self::Double(v),
            CqlValue::Counter(v) => Self::Counter(v),
            CqlValue::Time(v) => Self::Time(v),
            CqlValue::Timestamp(v) => Self::Timestamp(v),
            CqlValue::Text(v) => Self::Text(Box::new(v)),
            CqlValue::Ascii(v) => Self::Ascii(Box::new(v)),
            CqlValue::Blob(v) => Self::Blob(Box::new(v)),
            CqlValue::Uuid(v) => Self::Uuid(Box::new(v)),
            CqlValue::Timeuuid(v) => Self::Timeuuid(Box::new(v)),
            CqlValue::Inet(v) => Self::Inet(Box::new(v)),
            other => panic!(
                "CqlValue variant not supported for primary key: {other:?}. \
                 Only scalar CQL types are supported."
            ),
        }
    }
}

impl From<&CompactCqlValue> for CqlValue {
    fn from(v: &CompactCqlValue) -> Self {
        match v {
            CompactCqlValue::Empty => CqlValue::Empty,
            CompactCqlValue::Boolean(v) => CqlValue::Boolean(*v),
            CompactCqlValue::TinyInt(v) => CqlValue::TinyInt(*v),
            CompactCqlValue::SmallInt(v) => CqlValue::SmallInt(*v),
            CompactCqlValue::Int(v) => CqlValue::Int(*v),
            CompactCqlValue::Float(v) => CqlValue::Float(*v),
            CompactCqlValue::Date(v) => CqlValue::Date(*v),
            CompactCqlValue::BigInt(v) => CqlValue::BigInt(*v),
            CompactCqlValue::Double(v) => CqlValue::Double(*v),
            CompactCqlValue::Counter(v) => CqlValue::Counter(*v),
            CompactCqlValue::Time(v) => CqlValue::Time(*v),
            CompactCqlValue::Timestamp(v) => CqlValue::Timestamp(*v),
            CompactCqlValue::Text(v) => CqlValue::Text(v.as_ref().clone()),
            CompactCqlValue::Ascii(v) => CqlValue::Ascii(v.as_ref().clone()),
            CompactCqlValue::Blob(v) => CqlValue::Blob(v.as_ref().clone()),
            CompactCqlValue::Uuid(v) => CqlValue::Uuid(**v),
            CompactCqlValue::Timeuuid(v) => CqlValue::Timeuuid(**v),
            CompactCqlValue::Inet(v) => CqlValue::Inet(**v),
        }
    }
}

impl PartialEq for CompactCqlValue {
    fn eq(&self, other: &Self) -> bool {
        // Convert to CqlValue for comparison — reuses the driver's PartialEq.
        CqlValue::from(self) == CqlValue::from(other)
    }
}

impl Eq for CompactCqlValue {}

impl fmt::Debug for CompactCqlValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to CqlValue's Debug so hashing and display stay identical.
        CqlValue::from(self).fmt(f)
    }
}

// ─── PrimaryKey ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PrimaryKey(Vec<CompactCqlValue>);

impl PrimaryKey {
    /// Number of columns.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get the value at `index` as a [`CqlValue`].
    pub fn get(&self, index: usize) -> Option<CqlValue> {
        self.0.get(index).map(CqlValue::from)
    }
}

impl From<Vec<CqlValue>> for PrimaryKey {
    fn from(values: Vec<CqlValue>) -> Self {
        Self(values.into_iter().map(CompactCqlValue::from).collect())
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_cql_value_is_16_bytes() {
        assert_eq!(
            std::mem::size_of::<CompactCqlValue>(),
            16,
            "CompactCqlValue should be 16 bytes (discriminant + padding + 8-byte Box ptr)"
        );
    }

    #[test]
    fn cql_value_is_much_larger() {
        let cql_size = std::mem::size_of::<CqlValue>();
        let compact_size = std::mem::size_of::<CompactCqlValue>();
        assert!(
            cql_size >= compact_size * 2,
            "CqlValue ({cql_size}B) should be at least 2× CompactCqlValue ({compact_size}B)"
        );
    }

    #[test]
    fn roundtrip_int() {
        let pk: PrimaryKey = vec![CqlValue::Int(42)].into();
        assert_eq!(pk.len(), 1);
        assert_eq!(pk.get(0), Some(CqlValue::Int(42)));
        assert_eq!(pk.get(1), None);
    }

    #[test]
    fn roundtrip_multiple_columns() {
        let pk: PrimaryKey =
            vec![CqlValue::Int(1), CqlValue::Text("hello".to_string())].into();
        assert_eq!(pk.len(), 2);
        assert_eq!(pk.get(0), Some(CqlValue::Int(1)));
        assert_eq!(pk.get(1), Some(CqlValue::Text("hello".to_string())));
    }

    #[test]
    fn equality_and_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;

        let pk1: PrimaryKey =
            vec![CqlValue::Int(42), CqlValue::Text("foo".to_string())].into();
        let pk2: PrimaryKey =
            vec![CqlValue::Int(42), CqlValue::Text("foo".to_string())].into();
        let pk3: PrimaryKey = vec![CqlValue::Int(99)].into();

        assert_eq!(pk1, pk2);
        assert_ne!(pk1, pk3);

        let hash = |pk: &PrimaryKey| {
            let mut h = DefaultHasher::new();
            pk.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash(&pk1), hash(&pk2));
        assert_ne!(hash(&pk1), hash(&pk3));
    }
}
