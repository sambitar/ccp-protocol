package ccp

import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Pointer

/** JNA mapping of the kernel's C ABI. */
interface KernelLibrary : Library {
    fun ccp_alloc(length: NativeLong): Pointer?
    fun ccp_free(pointer: Pointer?, length: NativeLong)
    fun ccp_result_ptr(): Pointer
    fun ccp_result_len(): NativeLong
    fun ccp_canonicalize(pointer: Pointer?, length: NativeLong): Int
    fun ccp_decide(pointer: Pointer?, length: NativeLong): Int
    fun ccp_next_state(pointer: Pointer?, length: NativeLong): Int
    fun ccp_sign(pointer: Pointer?, length: NativeLong): Int
    fun ccp_verify(pointer: Pointer?, length: NativeLong): Int
    fun ccp_sign_document(pointer: Pointer?, length: NativeLong): Int
}

sealed class KernelResult<out T> {
    data class Ok<T>(val value: T) : KernelResult<T>()
    data class Failure(val code: String) : KernelResult<Nothing>()
}

/**
 * Kotlin façade over the portable CCP kernel.
 *
 * Load the native library with `-Djna.library.path=<dir containing
 * libccp_kernel.so>`.
 */
object Ccp {
    private val library: KernelLibrary by lazy {
        Native.load("ccp_kernel", KernelLibrary::class.java)
    }

    private enum class Operation {
        CANONICALIZE, DECIDE, NEXT_STATE, SIGN, VERIFY, SIGN_DOCUMENT
    }

    private fun invoke(operation: Operation, input: String): KernelResult<JsonElement> {
        val bytes = input.toByteArray(Charsets.UTF_8)
        val length = NativeLong(bytes.size.toLong())
        val pointer = if (bytes.isEmpty()) null else library.ccp_alloc(length)
        if (bytes.isNotEmpty() && pointer == null) {
            return KernelResult.Failure("outcome_unknown")
        }
        try {
            pointer?.write(0, bytes, 0, bytes.size)
            val code = when (operation) {
                Operation.CANONICALIZE -> library.ccp_canonicalize(pointer, length)
                Operation.DECIDE -> library.ccp_decide(pointer, length)
                Operation.NEXT_STATE -> library.ccp_next_state(pointer, length)
                Operation.SIGN -> library.ccp_sign(pointer, length)
                Operation.VERIFY -> library.ccp_verify(pointer, length)
                Operation.SIGN_DOCUMENT -> library.ccp_sign_document(pointer, length)
            }

            val resultLength = library.ccp_result_len().toLong().toInt()
            val output = library.ccp_result_ptr()
                .getByteArray(0, resultLength)
                .toString(Charsets.UTF_8)
            val envelope = JsonParser.parseString(output).asJsonObject
            val ok = envelope.get("ok")?.asBoolean ?: false
            if (code != 0 || !ok) {
                return KernelResult.Failure(
                    envelope.get("error")?.asString ?: "outcome_unknown"
                )
            }
            return KernelResult.Ok(envelope.get("value"))
        } finally {
            if (pointer != null) library.ccp_free(pointer, length)
        }
    }

    private fun stringResult(result: KernelResult<JsonElement>): KernelResult<String> =
        when (result) {
            is KernelResult.Failure -> result
            is KernelResult.Ok -> KernelResult.Ok(result.value.asString)
        }

    private fun objectResult(result: KernelResult<JsonElement>): KernelResult<JsonObject> =
        when (result) {
            is KernelResult.Failure -> result
            is KernelResult.Ok -> KernelResult.Ok(result.value.asJsonObject)
        }

    fun canonicalize(document: String): KernelResult<String> =
        stringResult(invoke(Operation.CANONICALIZE, document))

    fun decide(input: JsonObject): KernelResult<String> =
        stringResult(invoke(Operation.DECIDE, input.toString()))

    fun nextState(from: String?, event: String): KernelResult<String> {
        val payload = JsonObject().apply {
            if (from == null) add("from", JsonNull.INSTANCE) else addProperty("from", from)
            addProperty("event", event)
        }
        return stringResult(invoke(Operation.NEXT_STATE, payload.toString()))
    }

    fun sign(seedHex: String, messageHex: String): KernelResult<JsonObject> {
        val payload = JsonObject().apply {
            addProperty("seed_hex", seedHex)
            addProperty("message_hex", messageHex)
        }
        return objectResult(invoke(Operation.SIGN, payload.toString()))
    }

    fun verify(
        publicKeyHex: String,
        messageHex: String,
        signatureField: String,
    ): KernelResult<Boolean> {
        val payload = JsonObject().apply {
            addProperty("public_key_hex", publicKeyHex)
            addProperty("message_hex", messageHex)
            addProperty("signature_field", signatureField)
        }
        return when (val result = invoke(Operation.VERIFY, payload.toString())) {
            is KernelResult.Failure -> result
            is KernelResult.Ok -> KernelResult.Ok(result.value.asBoolean)
        }
    }

    fun signDocument(document: String, seedHex: String): KernelResult<JsonObject> {
        val payload = JsonObject().apply {
            addProperty("document", document)
            addProperty("seed_hex", seedHex)
        }
        return objectResult(invoke(Operation.SIGN_DOCUMENT, payload.toString()))
    }
}
