#ifndef CCP_H
#define CCP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Memory. `ccp_free` must receive the same length used with `ccp_alloc`. */
uint8_t *ccp_alloc(size_t length);
void ccp_free(uint8_t *pointer, size_t length);

/* The result buffer is valid until the next exported call. */
const uint8_t *ccp_result_ptr(void);
size_t ccp_result_len(void);

/*
 * Every operation returns 0 on success and 1 on a protocol error. The result
 * buffer always holds a JSON envelope:
 *   {"ok":true,"value":...}
 *   {"ok":false,"error":"code"}
 */
int32_t ccp_canonicalize(const uint8_t *pointer, size_t length);
int32_t ccp_decide(const uint8_t *pointer, size_t length);
int32_t ccp_next_state(const uint8_t *pointer, size_t length);
int32_t ccp_sign(const uint8_t *pointer, size_t length);
int32_t ccp_verify(const uint8_t *pointer, size_t length);
int32_t ccp_sign_document(const uint8_t *pointer, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* CCP_H */
