/*
 * oqs_bb84.c - Pure C BB84 QKD Implementation for OQS Provider
 * 
 * This file implements BB84 protocol in pure C for optimal performance
 * Adapt the protocol steps to match your specific BB84 algorithm logic
 */

#include "oqs_bb84.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

// Random number generator for BB84 simulation
static uint32_t bb84_rand_state = 1;

static uint32_t bb84_rand(void) {
    bb84_rand_state = bb84_rand_state * 1103515245 + 12345;
    return bb84_rand_state;
}

static void bb84_seed(uint32_t seed) {
    bb84_rand_state = seed;
}

static double bb84_random_double(void) {
    return (double)bb84_rand() / (double)UINT32_MAX;
}

OQS_BB84_CTX* oqs_bb84_new(size_t initial_bits) {
    OQS_BB84_CTX *ctx = malloc(sizeof(OQS_BB84_CTX));
    if (!ctx) return NULL;
    
    memset(ctx, 0, sizeof(OQS_BB84_CTX));
    ctx->initial_length = initial_bits;
    
    // Allocate arrays for BB84 protocol
    ctx->alice_bits = malloc(initial_bits);
    ctx->alice_bases = malloc(initial_bits);
    ctx->bob_bases = malloc(initial_bits);
    ctx->bob_bits = malloc(initial_bits);
    
    if (!ctx->alice_bits || !ctx->alice_bases || 
        !ctx->bob_bases || !ctx->bob_bits) {
        oqs_bb84_free(ctx);
        return NULL;
    }
    
    // Initialize configuration with defaults
    ctx->noise_level = 0.0;
    ctx->enable_error_correction = 1;
    ctx->enable_privacy_amplification = 1;
    ctx->error_rate = 0.0;
    ctx->eavesdropper_detected = 0;
    
    // Seed random number generator with current time + process-specific data
    bb84_seed((uint32_t)time(NULL) ^ (uint32_t)((uintptr_t)ctx & 0xFFFFFFFF));
    
    return ctx;
}

int oqs_bb84_generate_key(OQS_BB84_CTX *ctx) {
    if (!ctx) return BB84_ERROR_INVALID_PARAM;
    
    // ==========================================
    // ADJUST THIS SECTION TO MATCH YOUR BB84 ALGORITHM
    // ==========================================
    
    /* 
     * Step 1: Alice's Preparation Phase
     * Replace this with your specific Alice implementation
     */
    for (size_t i = 0; i < ctx->initial_length; i++) {
        // Generate random bit (0 or 1)
        ctx->alice_bits[i] = bb84_rand() & 1;
        
        // Generate random basis choice
        // 0 = rectilinear basis (|0⟩, |1⟩)  
        // 1 = diagonal basis (|+⟩, |-⟩)
        ctx->alice_bases[i] = bb84_rand() & 1;
        
        // TODO: Replace with your quantum state preparation logic
        // For example, if you have specific photon polarization encoding:
        // - 0° for |0⟩ in rectilinear
        // - 90° for |1⟩ in rectilinear  
        // - 45° for |+⟩ in diagonal
        // - 135° for |-⟩ in diagonal
    }
    
    /*
     * Step 2: Bob's Measurement Phase
     * Replace this with your specific Bob implementation
     */
    for (size_t i = 0; i < ctx->initial_length; i++) {
        // Bob randomly chooses measurement basis
        ctx->bob_bases[i] = bb84_rand() & 1;
        
        // TODO: Replace with your quantum measurement logic
        // This is where you'd implement your specific measurement process
    }
    
    /*
     * Step 3: Quantum Channel Simulation
     * Adjust this to match your channel model
     */
    for (size_t i = 0; i < ctx->initial_length; i++) {
        if (ctx->alice_bases[i] == ctx->bob_bases[i]) {
            // Same basis - Bob should get Alice's bit with possible noise
            if (bb84_random_double() < ctx->noise_level) {
                // Bit flip due to channel noise
                ctx->bob_bits[i] = 1 - ctx->alice_bits[i];
            } else {
                // Perfect transmission
                ctx->bob_bits[i] = ctx->alice_bits[i];
            }
        } else {
            // Different basis - random measurement result
            // TODO: Adjust this based on your quantum mechanical model
            // Standard BB84: 50% chance for each outcome
            ctx->bob_bits[i] = bb84_rand() & 1;
        }
    }
    
    /*
     * Step 4: Sifting Phase
     * This should match your sifting procedure
     */
    size_t sifted_count = 0;
    
    // Count bits where Alice and Bob used same basis
    for (size_t i = 0; i < ctx->initial_length; i++) {
        if (ctx->alice_bases[i] == ctx->bob_bases[i]) {
            sifted_count++;
        }
    }
    
    if (sifted_count == 0) {
        return BB84_ERROR_HIGH_ERROR_RATE;
    }
    
    // Allocate temporary arrays for sifted bits
    uint8_t *alice_sifted = malloc(sifted_count);
    uint8_t *bob_sifted = malloc(sifted_count);
    
    if (!alice_sifted || !bob_sifted) {
        free(alice_sifted);
        free(bob_sifted);
        return BB84_ERROR_MEMORY;
    }
    
    // Extract sifted bits
    size_t sifted_index = 0;
    for (size_t i = 0; i < ctx->initial_length; i++) {
        if (ctx->alice_bases[i] == ctx->bob_bases[i]) {
            alice_sifted[sifted_index] = ctx->alice_bits[i];
            bob_sifted[sifted_index] = ctx->bob_bits[i];
            sifted_index++;
        }
    }
    
    /*
     * Step 5: Error Detection and Correction
     * ADJUST THIS TO MATCH YOUR ERROR CORRECTION SCHEME
     */
    if (ctx->enable_error_correction && sifted_count > 0) {
        // Sample subset for error rate estimation
        size_t test_bits = sifted_count / 4; // Use 25% for testing
        if (test_bits > 100) test_bits = 100; // Cap at 100 bits
        if (test_bits < 10 && sifted_count >= 10) test_bits = 10; // Minimum 10 bits
        
        size_t error_count = 0;
        
        if (test_bits > 0) {
            // TODO: Implement your specific error detection method
            // This is a simple random sampling approach
            for (size_t i = 0; i < test_bits; i++) {
                size_t test_index = bb84_rand() % sifted_count;
                if (alice_sifted[test_index] != bob_sifted[test_index]) {
                    error_count++;
                }
            }
            
            ctx->error_rate = (double)error_count / test_bits;
            
            // Check if error rate exceeds security threshold
            if (ctx->error_rate > BB84_ERROR_THRESHOLD) {
                ctx->eavesdropper_detected = 1;
                free(alice_sifted);
                free(bob_sifted);
                return BB84_ERROR_EAVESDROPPER;
            }
            
            // TODO: Implement your error correction algorithm here
            // For example: Cascade, LDPC, BCH codes, etc.
            // This simple implementation assumes perfect error correction
            
            // Remove test bits from final key
            size_t final_count = sifted_count - test_bits;
            if (final_count > 0) {
                // Shift remaining bits (simplified approach)
                memmove(alice_sifted, alice_sifted + test_bits, final_count);
                sifted_count = final_count;
            }
        }
    }
    
    /*
     * Step 6: Privacy Amplification
     * ADJUST THIS TO MATCH YOUR PRIVACY AMPLIFICATION SCHEME
     */
    size_t final_key_bits = sifted_count;
    
    if (ctx->enable_privacy_amplification && sifted_count > 0) {
        // TODO: Implement your privacy amplification algorithm
        // Common approaches: Universal hashing, Toeplitz matrices, etc.
        
        // Simple approach: reduce key length based on error rate
        double reduction_factor = 1.0 - 2.0 * ctx->error_rate;
        if (reduction_factor < 0.5) reduction_factor = 0.5; // Minimum 50% retention
        
        final_key_bits = (size_t)(sifted_count * reduction_factor);
    }
    
    // Convert final bits to bytes
    size_t final_key_bytes = final_key_bits / 8;
    if (final_key_bytes == 0 && final_key_bits > 0) {
        final_key_bytes = 1; // At least one byte if we have any bits
    }
    
    if (final_key_bytes == 0) {
        free(alice_sifted);
        free(bob_sifted);
        return BB84_ERROR_HIGH_ERROR_RATE;
    }
    
    // Allocate final key buffer
    ctx->sifted_key = malloc(final_key_bytes);
    if (!ctx->sifted_key) {
        free(alice_sifted);
        free(bob_sifted);
        return BB84_ERROR_MEMORY;
    }
    
    // Pack bits into bytes
    memset(ctx->sifted_key, 0, final_key_bytes);
    for (size_t i = 0; i < final_key_bits; i++) {
        if (i < sifted_count && alice_sifted[i]) {
            ctx->sifted_key[i / 8] |= (1 << (i % 8));
        }
    }
    
    ctx->key_length = final_key_bytes;
    
    // Clean up
    free(alice_sifted);
    free(bob_sifted);
    
    return BB84_SUCCESS;
}

int oqs_bb84_get_key(OQS_BB84_CTX *ctx, uint8_t *key, size_t *key_len) {
    if (!ctx || !key_len) {
        return BB84_ERROR_INVALID_PARAM;
    }
    
    if (!ctx->sifted_key) {
        return BB84_ERROR_INVALID_PARAM;
    }
    
    // If key is NULL, just return the required size
    if (!key) {
        *key_len = ctx->key_length;
        return BB84_SUCCESS;  // Return success to indicate size is available
    }
    
    // Check if buffer is large enough
    if (*key_len < ctx->key_length) {
        *key_len = ctx->key_length;
        return BB84_ERROR_INVALID_PARAM; // Buffer too small
    }
    
    // Copy the key
    memcpy(key, ctx->sifted_key, ctx->key_length);
    *key_len = ctx->key_length;
    
    return BB84_SUCCESS;
}

void oqs_bb84_free(OQS_BB84_CTX *ctx) {
    if (!ctx) return;
    
    // Clear sensitive data before freeing
    if (ctx->alice_bits) {
        memset(ctx->alice_bits, 0, ctx->initial_length);
        free(ctx->alice_bits);
    }
    
    if (ctx->alice_bases) {
        memset(ctx->alice_bases, 0, ctx->initial_length);
        free(ctx->alice_bases);
    }
    
    if (ctx->bob_bases) {
        memset(ctx->bob_bases, 0, ctx->initial_length);
        free(ctx->bob_bases);
    }
    
    if (ctx->bob_bits) {
        memset(ctx->bob_bits, 0, ctx->initial_length);
        free(ctx->bob_bits);
    }
    
    if (ctx->sifted_key) {
        memset(ctx->sifted_key, 0, ctx->key_length);
        free(ctx->sifted_key);
    }
    
    memset(ctx, 0, sizeof(OQS_BB84_CTX));
    free(ctx);
}

// Configuration functions

int oqs_bb84_set_noise(OQS_BB84_CTX *ctx, double noise_level) {
    if (!ctx || noise_level < 0.0 || noise_level > 1.0) {
        return BB84_ERROR_INVALID_PARAM;
    }
    
    ctx->noise_level = noise_level;
    return BB84_SUCCESS;
}

int oqs_bb84_set_error_correction(OQS_BB84_CTX *ctx, int enable) {
    if (!ctx) {
        return BB84_ERROR_INVALID_PARAM;
    }
    
    ctx->enable_error_correction = enable ? 1 : 0;
    return BB84_SUCCESS;
}

double oqs_bb84_get_error_rate(OQS_BB84_CTX *ctx) {
    if (!ctx) {
        return -1.0;
    }
    
    return ctx->error_rate;
}

int oqs_bb84_eavesdropper_detected(OQS_BB84_CTX *ctx) {
    return ctx ? ctx->eavesdropper_detected : -1;
}