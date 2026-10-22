package ccp

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import kotlin.system.exitProcess

private const val SEED =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

private fun unwrap(result: KernelResult<JsonObject>): JsonObject = when (result) {
    is KernelResult.Ok -> result.value
    is KernelResult.Failure -> {
        System.err.println("kernel error: ${result.code}")
        exitProcess(1)
    }
}

fun main() {
    val identity = unwrap(Ccp.sign(SEED, ""))

    val manifest = JsonObject().apply {
        addProperty("ccp", "0.5-draft")
        add("provider", JsonObject().apply {
            addProperty("id", identity.get("key_id").asString)
            addProperty("name", "Example Service")
        })
        addProperty("version", 1)
        add("intents", JsonObject().apply {
            add("example.lookup", JsonObject().apply {
                addProperty("description", "Look up one item requested by the consumer")
                addProperty("params_schema", "schema:example.lookup.params.v1")
                addProperty("result_schema", "schema:example.lookup.result.v1")
                add("required_capabilities", JsonArray().apply { add("store.read") })
                addProperty("placement", "local")
                add("data_egress", JsonObject().apply {
                    addProperty("network", false)
                    add("fields", JsonArray())
                })
                add("suggested_limits", JsonObject().apply {
                    addProperty("calls_per_hour", 10)
                })
                addProperty("confirmation", "grant-policy")
            })
        })
    }

    val signedManifest = unwrap(Ccp.signDocument(manifest.toString(), SEED))
    val digest = "sha256:" + signedManifest.get("signing_input_sha256").asString

    val signal = JsonObject().apply {
        addProperty("ccp", "0.5-draft")
        addProperty("request_id", "req-kotlin-1")
        addProperty("grant_digest", digest)
        addProperty("intent", "example.lookup")
        add("params", JsonObject().apply { addProperty("item_id", "item-123") })
        addProperty("issued_at", "2026-10-22T12:00:00Z")
        addProperty("expires_at", "2026-10-22T12:01:00Z")
    }
    val signedSignal = unwrap(Ccp.signDocument(signal.toString(), SEED))

    println("manifest: ${signedManifest.get("wire").asString}")
    println("manifest digest: $digest")
    println("signal: ${signedSignal.get("wire").asString}")
}
