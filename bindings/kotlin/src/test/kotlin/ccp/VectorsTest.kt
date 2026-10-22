package ccp

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import kotlin.system.exitProcess

private const val INTENT_SPEC =
    """{"confirmation":"grant-policy","required_capabilities":["store.read"]}"""
private const val PARAMS_SCHEMA =
    """{"additionalProperties":false,"properties":{"item_id":{"type":"string"}},"required":["item_id"],"type":"object"}"""

private var cases = 0
private var failures = 0

private fun verifyCase(id: String, condition: Boolean, detail: () -> String) {
    cases += 1
    if (!condition) {
        failures += 1
        System.err.println("FAIL $id: ${detail()}")
    }
}

private fun load(relative: String): JsonObject =
    JsonParser.parseString(File(relative).readText()).asJsonObject

private fun field(value: JsonElement, name: String): String =
    value.asJsonObject.get(name).asString

private fun canonical(path: String) {
    for (element in load(path).getAsJsonArray("vectors")) {
        val vector = element.asJsonObject
        val id = "$path/${vector.get("id").asString}"
        val result = Ccp.canonicalize(vector.get("document").asString)
        if (vector.has("expect_error")) {
            val expected = vector.get("expect_error").asString
            verifyCase(id, result is KernelResult.Failure && result.code == expected) {
                "expected $expected, got $result"
            }
        } else {
            val expected = vector.get("expected_canonical").asString
            verifyCase(id, result is KernelResult.Ok && result.value == expected) {
                "expected $expected, got $result"
            }
        }
    }
}

private fun validation(path: String) {
    val intentSpec = JsonParser.parseString(INTENT_SPEC)
    val paramsSchema = JsonParser.parseString(PARAMS_SCHEMA)
    for (element in load(path).getAsJsonArray("vectors")) {
        val vector = element.asJsonObject
        val context = vector.getAsJsonObject("context")
        val input = JsonObject().apply {
            add("grant", vector.get("grant"))
            add("signal", vector.get("signal"))
            addProperty("signer", field(vector, "signer"))
            addProperty("now", field(context, "now"))
            add("seen", context.get("seen"))
            add("counters", context.get("counters"))
            add("intent_spec", intentSpec)
            add("params_schema", paramsSchema)
        }
        val expected = field(vector, "expected")
        val result = Ccp.decide(input)
        verifyCase("$path/${field(vector, "id")}", result is KernelResult.Ok && result.value == expected) {
            "expected $expected, got $result"
        }
    }
}

private fun stateMachine() {
    for (element in load("test-vectors/state-machine.json").getAsJsonArray("vectors")) {
        val vector = element.asJsonObject
        val result = Ccp.nextState(field(vector, "from"), field(vector, "event"))
        val expected = field(vector, "to")
        verifyCase("state/${field(vector, "id")}", result is KernelResult.Ok && result.value == expected) {
            "expected $expected, got $result"
        }
    }
}

private fun ed25519() {
    val file = load("test-vectors/ed25519.json")
    for (element in file.getAsJsonArray("kat_vectors")) {
        val vector = element.asJsonObject
        val id = "kat/${field(vector, "id")}"
        val result = Ccp.sign(field(vector, "secret_key_hex"), field(vector, "message_hex"))
        val value = (result as? KernelResult.Ok)?.value
        verifyCase(id, value != null && field(value, "public_key_hex") == field(vector, "public_key_hex")) {
            "public key: $result"
        }
        verifyCase(id, value != null && field(value, "key_id") == field(vector, "key_id")) {
            "key id: $result"
        }
        verifyCase(id, value != null && field(value, "signature_hex") == field(vector, "signature_hex")) {
            "signature: $result"
        }
        verifyCase(id, value != null && field(value, "signature_field") == field(vector, "signature_field")) {
            "signature field: $result"
        }
        val verified = Ccp.verify(
            field(vector, "public_key_hex"),
            field(vector, "message_hex"),
            field(vector, "signature_field"),
        )
        verifyCase(id, verified is KernelResult.Ok && verified.value) {
            "verification: $verified"
        }
    }

    for (element in file.getAsJsonArray("signing_vectors")) {
        val vector = element.asJsonObject
        val id = "sig/${field(vector, "id")}"
        val result = Ccp.signDocument(field(vector, "document"), field(vector, "seed_hex"))
        val value = (result as? KernelResult.Ok)?.value
        for (name in listOf("public_key_hex", "key_id", "signing_input_sha256", "signature_field", "wire")) {
            verifyCase(id, value != null && field(value, name) == field(vector, name)) {
                "$name: $result"
            }
        }
    }
}

fun main() {
    canonical("test-vectors/canonical-json.json")
    canonical("test-vectors/v2/canonical-json.json")
    validation("test-vectors/validation.json")
    validation("test-vectors/v2/validation.json")
    stateMachine()
    ed25519()

    println("kotlin: $cases checks, ${cases - failures} passed, $failures failed")
    exitProcess(if (failures == 0) 0 else 1)
}
