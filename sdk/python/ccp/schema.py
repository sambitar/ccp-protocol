"""A minimal JSON Schema subset validator per CCP §25.3.

Supports the frozen subset used by the profile: ``type``, ``properties``,
``required``, ``additionalProperties``, ``items``, ``enum``, ``const``,
numeric bounds and ``multipleOf``, string length, array length and
uniqueness, and ``pattern``. Unknown keywords are ignored.

This is a reference validator, not a full JSON Schema implementation.
"""

import re


class SchemaError(ValueError):
    pass


def validate(value, schema):
    """Return a list of human-readable violations (empty means valid)."""
    errors = []
    _validate(value, schema, "$", errors)
    return errors


def is_valid(value, schema):
    return not validate(value, schema)


def _type_ok(value, name):
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    raise SchemaError("unsupported type: %r" % (name,))


def _validate(value, schema, path, errors):
    if schema is False:
        errors.append("%s: not allowed" % path)
        return
    if schema is True or schema is None:
        return

    expected = schema.get("type")
    if expected is not None:
        names = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(value, n) for n in names):
            errors.append("%s: expected %s" % (path, "/".join(names)))
            return

    if "const" in schema and value != schema["const"]:
        errors.append("%s: must equal %r" % (path, schema["const"]))
    if "enum" in schema and value not in schema["enum"]:
        errors.append("%s: must be one of %r" % (path, schema["enum"]))

    if isinstance(value, bool):
        return

    if isinstance(value, (int, float)):
        _validate_number(value, schema, path, errors)
    if isinstance(value, str):
        _validate_string(value, schema, path, errors)
    if isinstance(value, list):
        _validate_array(value, schema, path, errors)
    if isinstance(value, dict):
        _validate_object(value, schema, path, errors)


def _validate_number(value, schema, path, errors):
    if "minimum" in schema and value < schema["minimum"]:
        errors.append("%s: below minimum" % path)
    if "maximum" in schema and value > schema["maximum"]:
        errors.append("%s: above maximum" % path)
    if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
        errors.append("%s: not above exclusiveMinimum" % path)
    if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
        errors.append("%s: not below exclusiveMaximum" % path)
    if "multipleOf" in schema:
        step = schema["multipleOf"]
        if step:
            if (isinstance(value, int) and not isinstance(value, bool)
                    and isinstance(step, int)):
                if value % step != 0:
                    errors.append("%s: not a multiple of %r" % (path, step))
            elif abs(value / step - round(value / step)) > 1e-9:
                errors.append("%s: not a multiple of %r" % (path, step))


def _validate_string(value, schema, path, errors):
    if "minLength" in schema and len(value) < schema["minLength"]:
        errors.append("%s: shorter than minLength" % path)
    if "maxLength" in schema and len(value) > schema["maxLength"]:
        errors.append("%s: longer than maxLength" % path)
    if "pattern" in schema and re.search(schema["pattern"], value) is None:
        errors.append("%s: does not match pattern" % path)


def _validate_array(value, schema, path, errors):
    if "minItems" in schema and len(value) < schema["minItems"]:
        errors.append("%s: fewer than minItems" % path)
    if "maxItems" in schema and len(value) > schema["maxItems"]:
        errors.append("%s: more than maxItems" % path)
    if schema.get("uniqueItems"):
        if len({repr(v) for v in value}) != len(value):
            errors.append("%s: items are not unique" % path)
    items = schema.get("items")
    if items is not None:
        for index, item in enumerate(value):
            _validate(item, items, "%s[%d]" % (path, index), errors)


def _validate_object(value, schema, path, errors):
    properties = schema.get("properties", {})
    for name in schema.get("required", []):
        if name not in value:
            errors.append("%s.%s: required" % (path, name))
    additional = schema.get("additionalProperties", True)
    for name, item in value.items():
        if name in properties:
            _validate(item, properties[name], "%s.%s" % (path, name), errors)
        elif additional is False:
            errors.append("%s.%s: additional property not allowed" % (path, name))
        elif isinstance(additional, dict):
            _validate(item, additional, "%s.%s" % (path, name), errors)
