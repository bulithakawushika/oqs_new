// test_bb84_kem.c - Test BB84 QKD + ML-KEM Hybrid Implementation
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

int test_bb84_kem(const char *kem_name) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *keypair = NULL;
    unsigned char *pubkey = NULL, *privkey = NULL;
    unsigned char *ct = NULL, *ss1 = NULL, *ss2 = NULL;
    size_t pubkey_len = 0, privkey_len = 0;
    size_t ct_len = 0, ss1_len = 0, ss2_len = 0;
    int ret = 0;

    printf("\n=== Testing %s ===\n", kem_name);

    // Key generation - specify the provider properties
    ctx = EVP_PKEY_CTX_new_from_name(NULL, kem_name, "provider=oqsprovider");
    if (!ctx) {
        printf("ERROR: Failed to create context for %s\n", kem_name);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("ERROR: Keygen init failed\n");
        goto err;
    }

    if (EVP_PKEY_generate(ctx, &keypair) <= 0) {
        printf("ERROR: Key generation failed\n");
        goto err;
    }
    printf("✓ Key pair generated\n");

    // Get public key
    if (EVP_PKEY_get_octet_string_param(keypair, "pub", NULL, 0, &pubkey_len) != 1) {
        printf("ERROR: Failed to get public key length\n");
        goto err;
    }
    pubkey = OPENSSL_malloc(pubkey_len);
    if (EVP_PKEY_get_octet_string_param(keypair, "pub", pubkey, pubkey_len, &pubkey_len) != 1) {
        printf("ERROR: Failed to get public key\n");
        goto err;
    }
    print_hex("Public key", pubkey, pubkey_len);

    // Get private key
    if (EVP_PKEY_get_octet_string_param(keypair, "priv", NULL, 0, &privkey_len) != 1) {
        printf("ERROR: Failed to get private key length\n");
        goto err;
    }
    privkey = OPENSSL_malloc(privkey_len);
    if (EVP_PKEY_get_octet_string_param(keypair, "priv", privkey, privkey_len, &privkey_len) != 1) {
        printf("ERROR: Failed to get private key\n");
        goto err;
    }
    print_hex("Private key", privkey, privkey_len);

    // Encapsulation
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new(keypair, NULL);
    if (!ctx) {
        printf("ERROR: Failed to create encap context\n");
        goto err;
    }

    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) {
        printf("ERROR: Encapsulate init failed\n");
        goto err;
    }

    // Determine buffer sizes
    if (EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss1_len) <= 0) {
        printf("ERROR: Failed to get encapsulation sizes\n");
        goto err;
    }

    ct = OPENSSL_malloc(ct_len);
    ss1 = OPENSSL_malloc(ss1_len);

    // Perform encapsulation
    if (EVP_PKEY_encapsulate(ctx, ct, &ct_len, ss1, &ss1_len) <= 0) {
        printf("ERROR: Encapsulation failed\n");
        goto err;
    }
    printf("✓ Encapsulation successful\n");
    print_hex("Ciphertext", ct, ct_len);
    print_hex("Shared secret (encap)", ss1, ss1_len);

    // Check if BB84 was simulated (you'd see this in debug output)
    printf("Note: BB84 QKD simulation should have occurred during encapsulation\n");

    // Decapsulation
    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        printf("ERROR: Decapsulate init failed\n");
        goto err;
    }

    ss2_len = ss1_len;
    ss2 = OPENSSL_malloc(ss2_len);

    if (EVP_PKEY_decapsulate(ctx, ss2, &ss2_len, ct, ct_len) <= 0) {
        printf("ERROR: Decapsulation failed\n");
        goto err;
    }
    printf("✓ Decapsulation successful\n");
    print_hex("Shared secret (decap)", ss2, ss2_len);

    // Verify shared secrets match
    if (ss1_len != ss2_len || memcmp(ss1, ss2, ss1_len) != 0) {
        printf("ERROR: Shared secrets don't match!\n");
        goto err;
    }
    printf("✓ Shared secrets match! (length: %zu bytes)\n", ss1_len);
    
    ret = 1;

err:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(keypair);
    OPENSSL_free(pubkey);
    OPENSSL_free(privkey);
    OPENSSL_free(ct);
    OPENSSL_free(ss1);
    OPENSSL_free(ss2);
    
    return ret;
}

int main() {
    // Load the OQS provider
    OSSL_PROVIDER *oqsprov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!oqsprov) {
        printf("Failed to load OQS provider\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("OQS Provider loaded successfully\n");

    // Test all BB84 hybrid algorithms
    const char *algorithms[] = {
        "bb84_mlkem768_x25519",
        "bb84_mlkem1024_p384",
        "bb84_mlkem768_p256"
    };

    int success_count = 0;
    for (int i = 0; i < 3; i++) {
        if (test_bb84_kem(algorithms[i])) {
            success_count++;
        }
    }

    printf("\n=== Summary ===\n");
    printf("Tests passed: %d/3\n", success_count);

    OSSL_PROVIDER_unload(oqsprov);
    return (success_count == 3) ? 0 : 1;
}