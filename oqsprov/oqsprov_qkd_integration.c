#ifndef OQS_QKD_KEM_H
#define OQS_QKD_KEM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// QKD hybrid algorithm constants
#define QKD_HYB_MAX_PUBLICKEY_LENGTH 2048
#define QKD_HYB_MAX_SECRETKEY_LENGTH 2048
#define QKD_HYB_MAX_CIPHERTEXT_LENGTH 2048
#define QKD_HYB_SHARED_SECRET_LENGTH 32

// QKD hybrid algorithm support
#define QKD_SUPPORTED_ALGORITHMS 3

// QKD algorithm identifiers
typedef enum {
    QKD_ALG_MLKEM768_X25519,
    QKD_ALG_MLKEM1024_P384,
    QKD_ALG_MLKEM768_P256
} qkd_algorithm_id_t;

/**
 * Get parameters for a QKD hybrid algorithm
 * 
 * @param algorithm Algorithm name (e.g., "qkd_mlkem768_x25519")
 * @param pk_len Public key length (output)
 * @param sk_len Secret key length (output)
 * @param ct_len Ciphertext length (output)
 * @param ss_len Shared secret length (output)
 * @return 0 on success, -1 on error
 */
int oqs_qkd_hyb_get_params(const char *algorithm, 
                           size_t *pk_len, size_t *sk_len, 
                           size_t *ct_len, size_t *ss_len);

/**
 * Generate a QKD hybrid key pair
 * 
 * @param pk Public key buffer (output)
 * @param sk Secret key buffer (output) 
 * @param algorithm Algorithm name
 * @return 0 on success, -1 on error
 */
int oqs_qkd_hyb_keypair(unsigned char *pk, unsigned char *sk, 
                        const char *algorithm);

/**
 * QKD hybrid encapsulation
 * 
 * @param ct Ciphertext buffer (output)
 * @param ss Shared secret buffer (output)
 * @param pk Public key
 * @param algorithm Algorithm name
 * @return 0 on success, -1 on error
 */
int oqs_qkd_hyb_encaps(unsigned char *ct, unsigned char *ss, 
                       const unsigned char *pk, const char *algorithm);

/**
 * QKD hybrid decapsulation
 * 
 * @param ss Shared secret buffer (output)
 * @param ct Ciphertext
 * @param sk Secret key
 * @param algorithm Algorithm name
 * @return 0 on success, -1 on error
 */
int oqs_qkd_hyb_decaps(unsigned char *ss, const unsigned char *ct,
                       const unsigned char *sk, const char *algorithm);

/**
 * Check if QKD is available for the specified algorithm
 * 
 * @param algorithm Algorithm name
 * @return 1 if available, 0 if not
 */
int oqs_qkd_hyb_is_available(const char *algorithm);

/**
 * Get the QKD algorithm ID from name
 * 
 * @param algorithm Algorithm name
 * @return Algorithm ID, or -1 if not found
 */
int oqs_qkd_hyb_get_algorithm_id(const char *algorithm);

/**
 * Get algorithm name from ID
 * 
 * @param id Algorithm ID
 * @return Algorithm name, or NULL if invalid
 */
const char* oqs_qkd_hyb_get_algorithm_name(qkd_algorithm_id_t id);

#ifdef __cplusplus
}
#endif

#endif /* OQS_QKD_KEM_H */