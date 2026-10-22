//! Minimal JSON Schema subset validator (§25.3).

use num_bigint::BigUint;
use num_traits::Zero;
use regex::Regex;

use crate::json::serialize;
use crate::value::Value;

fn member<'a>(entries: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn type_ok(value: &Value, name: &str) -> bool {
    match name {
        "object" => matches!(value, Value::Object(_)),
        "array" => matches!(value, Value::Array(_)),
        "string" => matches!(value, Value::Str(_)),
        "integer" | "number" => matches!(value, Value::Int(_)),
        "boolean" => matches!(value, Value::Bool(_)),
        "null" => matches!(value, Value::Null),
        _ => false,
    }
}

/// True when `value` satisfies the subset schema.
pub fn is_valid(value: &Value, schema: &Value) -> bool {
    match schema {
        Value::Bool(false) => false,
        Value::Bool(true) | Value::Null => true,
        Value::Object(entries) => check_object(value, entries),
        _ => true,
    }
}

fn check_object(value: &Value, schema: &[(String, Value)]) -> bool {
    if let Some(expected) = member(schema, "type") {
        let by_name = match expected {
            Value::Str(name) => vec![name.as_str()],
            Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
            _ => return false,
        };
        if !by_name.iter().any(|name| type_ok(value, name)) {
            return false;
        }
    }

    if let Some(constant) = member(schema, "const") {
        if value != constant {
            return false;
        }
    }
    if let Some(Value::Array(options)) = member(schema, "enum") {
        if !options.iter().any(|option| option == value) {
            return false;
        }
    }

    match value {
        Value::Int(number) => check_number(number, schema),
        Value::Str(text) => check_string(text, schema),
        Value::Array(items) => check_array(items, schema),
        Value::Object(entries) => check_properties(entries, schema),
        _ => true,
    }
}

fn check_number(number: &BigUint, schema: &[(String, Value)]) -> bool {
    if let Some(Value::Int(minimum)) = member(schema, "minimum") {
        if number < minimum {
            return false;
        }
    }
    if let Some(Value::Int(maximum)) = member(schema, "maximum") {
        if number > maximum {
            return false;
        }
    }
    if let Some(Value::Int(minimum)) = member(schema, "exclusiveMinimum") {
        if number <= minimum {
            return false;
        }
    }
    if let Some(Value::Int(maximum)) = member(schema, "exclusiveMaximum") {
        if number >= maximum {
            return false;
        }
    }
    if let Some(Value::Int(step)) = member(schema, "multipleOf") {
        if !step.is_zero() && (number % step) != BigUint::zero() {
            return false;
        }
    }
    true
}

fn check_string(text: &str, schema: &[(String, Value)]) -> bool {
    let length = BigUint::from(text.chars().count());
    if let Some(Value::Int(minimum)) = member(schema, "minLength") {
        if length < *minimum {
            return false;
        }
    }
    if let Some(Value::Int(minimum)) = member(schema, "maxLength") {
        if length > *minimum {
            return false;
        }
    }
    if let Some(Value::Str(pattern)) = member(schema, "pattern") {
        match Regex::new(pattern) {
            Ok(regex) => {
                if !regex.is_match(text) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

fn check_array(items: &[Value], schema: &[(String, Value)]) -> bool {
    let length = BigUint::from(items.len());
    if let Some(Value::Int(minimum)) = member(schema, "minItems") {
        if length < *minimum {
            return false;
        }
    }
    if let Some(Value::Int(maximum)) = member(schema, "maxItems") {
        if length > *maximum {
            return false;
        }
    }
    if let Some(Value::Bool(true)) = member(schema, "uniqueItems") {
        let mut seen = std::collections::HashSet::new();
        for item in items {
            match serialize(item) {
                Ok(key) => {
                    if !seen.insert(key) {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
    }
    if let Some(item_schema) = member(schema, "items") {
        if !items.iter().all(|item| is_valid(item, item_schema)) {
            return false;
        }
    }
    true
}

fn check_properties(entries: &[(String, Value)], schema: &[(String, Value)]) -> bool {
    let properties = member(schema, "properties");
    if let Some(Value::Array(required)) = member(schema, "required") {
        for name in required {
            if let Value::Str(name) = name {
                if !entries.iter().any(|(key, _)| key == name) {
                    return false;
                }
            }
        }
    }

    let additional = member(schema, "additionalProperties");
    for (name, item) in entries {
        let property = match properties {
            Some(Value::Object(properties)) => member(properties, name),
            _ => None,
        };
        if let Some(property) = property {
            if !is_valid(item, property) {
                return false;
            }
            continue;
        }
        match additional {
            Some(Value::Bool(false)) => return false,
            Some(schema @ Value::Object(_)) if !is_valid(item, schema) => return false,
            _ => {}
        }
    }
    true
}
