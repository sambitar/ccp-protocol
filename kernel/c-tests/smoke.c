#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ccp.h"

static char *call(int32_t (*fn)(const uint8_t *, size_t), const char *input) {
    size_t length = strlen(input);
    uint8_t *buffer = ccp_alloc(length);
    if (buffer == NULL && length > 0) {
        fprintf(stderr, "ccp_alloc failed\n");
        exit(1);
    }
    memcpy(buffer, input, length);
    int32_t code = fn(buffer, length);
    ccp_free(buffer, length);

    const uint8_t *result = ccp_result_ptr();
    size_t result_length = ccp_result_len();
    char *copy = malloc(result_length + 1);
    if (copy == NULL) {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }
    memcpy(copy, result, result_length);
    copy[result_length] = '\0';

    int32_t expected_code = strstr(copy, "\"ok\":true") != NULL ? 0 : 1;
    if (code != expected_code) {
        fprintf(stderr, "envelope/return mismatch: %s\n", copy);
        exit(1);
    }
    return copy;
}

static void expect_equal(const char *label, const char *got, const char *want) {
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "%s\n  got:  %s\n  want: %s\n", label, got, want);
        exit(1);
    }
}

static void expect_contains(const char *label, const char *got, const char *want) {
    if (strstr(got, want) == NULL) {
        fprintf(stderr, "%s\n  got: %s\n  want substring: %s\n", label, got, want);
        exit(1);
    }
}

int main(void) {
    char *result;

    result = call(ccp_canonicalize, "{\"b\":1,\"a\":2}");
    expect_equal("canonical key sort", result,
                 "{\"ok\":true,\"value\":\"{\\\"a\\\":2,\\\"b\\\":1}\"}");
    free(result);

    result = call(ccp_canonicalize, "{\"e\\u0301\":1,\"f\":2}");
    expect_equal("normalized key sort", result,
                 "{\"ok\":true,\"value\":\"{\\\"f\\\":2,\\\"\xC3\xA9\\\":1}\"}");
    free(result);

    result = call(ccp_canonicalize, "{\"a\":1,\"\\u0061\":2}");
    expect_equal("duplicate key", result,
                 "{\"error\":\"duplicate\",\"ok\":false}");
    free(result);

    result = call(ccp_next_state,
                  "{\"from\":\"authorized\",\"event\":\"no_confirmation\"}");
    expect_equal("state machine", result,
                 "{\"ok\":true,\"value\":\"executing\"}");
    free(result);

    const char *decision_input =
        "{\"grant\":{\"id\":\"g-0001\","
        "\"requester_key\":\"key:ed25519:AAAABBBBCCCCDDDDEEEEFFFF0000111122223333\","
        "\"contact_id\":\"c-0001\","
        "\"manifest_digest\":\"sha256:abababababababababababababababababababababababababababababababab\","
        "\"manifest_version\":1,\"intents\":[\"example.lookup\"],"
        "\"limits\":{\"calls_per_hour\":10},"
        "\"created_at\":\"2026-10-22T10:00:00Z\","
        "\"expires_at\":\"2026-10-22T13:00:00Z\","
        "\"confirmation\":{\"example.lookup\":\"none\"},"
        "\"capabilities\":[\"store.read\"],\"placement\":[\"local\"],"
        "\"egress\":{\"network\":false},\"state\":\"active\","
        "\"state_reason\":null},"
        "\"signal\":{\"ccp\":\"0.4-draft\",\"request_id\":\"req-0001\","
        "\"grant_digest\":\"sha256:abababababababababababababababababababababababababababababababab\","
        "\"intent\":\"example.lookup\",\"params\":{\"item_id\":\"item-123\"},"
        "\"issued_at\":\"2026-10-22T12:00:00Z\","
        "\"expires_at\":\"2026-10-22T12:01:00Z\"},"
        "\"signer\":\"key:ed25519:AAAABBBBCCCCDDDDEEEEFFFF0000111122223333\","
        "\"now\":\"2026-10-22T12:00:30Z\",\"seen\":[],"
        "\"counters\":{\"calls_per_hour\":0},"
        "\"intent_spec\":{\"confirmation\":\"grant-policy\","
        "\"required_capabilities\":[\"store.read\"]},"
        "\"params_schema\":{\"additionalProperties\":false,"
        "\"properties\":{\"item_id\":{\"type\":\"string\"}},"
        "\"required\":[\"item_id\"],\"type\":\"object\"}}";
    result = call(ccp_decide, decision_input);
    expect_equal("decision", result,
                 "{\"ok\":true,\"value\":\"authorized\"}");
    free(result);

    const char *seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const char *public_key =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const char *signature_field =
        "ed25519:5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc-bRr0lv18FlbviRlUUFDjnoQCw";

    char sign_input[512];
    snprintf(sign_input, sizeof(sign_input),
             "{\"seed_hex\":\"%s\",\"message_hex\":\"\"}", seed);
    result = call(ccp_sign, sign_input);
    expect_contains("ed25519 public key", result, public_key);
    expect_contains("ed25519 signature", result, signature_field);
    free(result);

    char verify_input[512];
    snprintf(verify_input, sizeof(verify_input),
             "{\"message_hex\":\"\",\"public_key_hex\":\"%s\","
             "\"signature_field\":\"%s\"}",
             public_key, signature_field);
    result = call(ccp_verify, verify_input);
    expect_equal("ed25519 verify", result, "{\"ok\":true,\"value\":true}");
    free(result);

    printf("c smoke: ok\n");
    return 0;
}
