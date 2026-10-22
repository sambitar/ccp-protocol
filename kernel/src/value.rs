use num_bigint::BigUint;

/// A JSON value in the CCP profile: non-negative integers only, and objects
/// preserve their input order until canonical serialization sorts the keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(BigUint),
    Str(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<&BigUint> {
        match self {
            Value::Int(value) => Some(value),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Insert or replace a key on an object. Used when completing a signed
    /// document; non-objects are left unchanged.
    pub fn set(&mut self, key: &str, value: Value) {
        if let Value::Object(entries) = self {
            if let Some(entry) = entries.iter_mut().find(|(name, _)| name == key) {
                entry.1 = value;
            } else {
                entries.push((key.to_string(), value));
            }
        }
    }

    pub fn remove(&mut self, key: &str) {
        if let Value::Object(entries) = self {
            entries.retain(|(name, _)| name != key);
        }
    }
}
