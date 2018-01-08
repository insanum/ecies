
/*
 * Home: https://github.com/insanum/ecies
 * Author: Eric Davis <edavis@insanum.com>
 */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>

#define err(fmt, ...)                                \
        do {                                         \
                printf("ERROR:" fmt, ##__VA_ARGS__); \
                exit(1);                             \
        } while (0)

#define log(fmt, ...)                       \
        do {                                \
                printf(fmt, ##__VA_ARGS__); \
        } while (0)

/*
 * This function takes a buffer with binary data and dumps
 * out a hex string prefixed with a label.
 */
void dump_hex(char *label, uint8_t *buf, int len)
{
        int i;
        log("%-10s: ", label);
        for (i = 0; i < len; ++i) { log("%02x", buf[i]); }
        log("\n");
}

/* Convert an EC key's public key to a binary array. */
int ec_key_public_key_to_bin(ecc_key   *ec_key,
                             uint8_t  **pubk,     // out (must free)
                             uint32_t  *pubk_len) // out
{
        uint8_t  x[4096];
        uint32_t x_len = 4096;
        uint8_t  y[4096];
        uint32_t y_len = 4096;

        if (wc_ecc_export_public_raw(ec_key, x, &x_len, y, &y_len) != 0)
                err("Failed to export public key to binary\n");

        *pubk_len = (1 + x_len + y_len);

        if ((*pubk = malloc(*pubk_len)) == NULL)
                err("Failed to allocate memory for the public key\n");

        memset(*pubk, 0, *pubk_len);
        *(*pubk) = 4;
        memcpy(*pubk + 1, x, x_len);
        memcpy(*pubk + 1 + x_len, y, y_len);

        return 0;
}

/* Convert an EC key's private key to a binary array. */
int ec_key_private_key_to_bin(ecc_key   *ec_key,
                              uint8_t  **privk,     // out (must free)
                              uint32_t  *privk_len) // out
{
        uint8_t  k[4096];
        uint32_t k_len = 4096;

        if (wc_ecc_export_private_only(ec_key, k, &k_len) != 0)
                err("Failed to export private key to binary\n");

        *privk_len = k_len;

        if ((*privk = malloc(*privk_len)) == NULL)
                err("Failed to allocate memory for the private key\n");

        memset(*privk, 0, *privk_len);
        memcpy(*privk, k, k_len);

        return 0;
}

/* (TX) Generate an ephemeral EC key and associated shared symmetric key. */
int ecies_transmitter_generate_symkey(const int        curve,
                                      const uint8_t   *peer_pubk,
                                      const uint32_t   peer_pubk_len,
                                      uint8_t        **epubk,         // out (must free)
                                      uint32_t        *epubk_len,     // out
                                      uint8_t        **skey,          // out (must free)
                                      uint32_t        *skey_len)      // out
{
        RNG       rng;
        ecc_key   ec_key;
        int       size;
        ecc_point peer_pubk_point;

        wc_InitRng(&rng);
        wc_ecc_init(&ec_key);

        size = wc_ecc_get_curve_size_from_id(curve);

        if (wc_ecc_make_key_ex(&rng, size, &ec_key, curve) != 0)
                err("Failed to generate a new key on the curve\n");

        /* Allocate a buffer to hold the shared symmetric key. */
        *skey_len = size;
        if ((*skey = malloc(*skey_len)) == NULL)
                err("Failed to allocate memory for the symmetric key\n");

        if (wc_ecc_import_point_der((uint8_t *)peer_pubk, peer_pubk_len,
                                    curve, &peer_pubk_point) != 0)
                err("Failed to import public key to an EC point\n");

        if (wc_ecc_shared_secret_ex(&ec_key, &peer_pubk_point,
                                    *skey, skey_len) != 0)
                err("Failed to generate a shared secret key\n");

        /* Write the ephemeral key's public key to the output buffer. */
        ec_key_public_key_to_bin(&ec_key, epubk, epubk_len);

        /*
         * NOTE: The private key is thrown away here...
         * With ECIES the transmitter EC key pair is a one time use only.
         */

        return 0;
}

/* (RX) Generate the shared symmetric key. */
int ecies_receiver_generate_symkey(ecc_key         *ec_key,
                                   int              curve,
                                   const uint8_t   *peer_pubk,
                                   const uint32_t   peer_pubk_len,
                                   uint8_t        **skey,          // out (must free)
                                   uint32_t        *skey_len)      // out
{
        int       size;
        ecc_point peer_pubk_point;

        size = wc_ecc_get_curve_size_from_id(curve);

        /* Allocate a buffer to hold the shared symmetric key. */
        *skey_len = size;
        if ((*skey = malloc(*skey_len)) == NULL)
                err("Failed to allocate memory for the symmetric key\n");

        if (wc_ecc_import_point_der((uint8_t *)peer_pubk, peer_pubk_len,
                                    curve, &peer_pubk_point) != 0)
                err("Failed to import public key to an EC point\n");

        if (wc_ecc_shared_secret_ex(ec_key, &peer_pubk_point,
                                    *skey, skey_len) != 0)
                err("Failed to generate a shared secret key\n");

        return 0;
}

/* Encrypt plaintext data using 256b AES-GCM. */
int aes_gcm_256b_encrypt(uint8_t   *plaintext,
                         uint32_t   plaintext_len,
                         uint8_t   *skey,
                         uint32_t   skey_len,
                         uint8_t   *aad,
                         uint32_t   aad_len,
                         uint8_t  **iv,             // out (must free)
                         uint8_t   *iv_len,         // out
                         uint8_t  **tag,            // out (must free)
                         uint8_t   *tag_len,        // out
                         uint8_t  **ciphertext,     // out (must free)
                         uint8_t   *ciphertext_len) // out
{
        RNG rng;
        Aes aes;

        wc_InitRng(&rng);

        wc_AesInit(&aes, NULL, 0);

        /* Allocate buffers for the IV, tag, and ciphertext. */

        *iv_len = 12;
        if ((*iv = malloc(*iv_len)) == NULL)
                err("Failed to allocate memory for the IV\n");

        *tag_len = 12;
        if ((*tag = malloc(*tag_len)) == NULL)
                err("Failed to allocate memory for the auth tag\n");

        *ciphertext_len = plaintext_len;
        if ((*ciphertext = malloc((plaintext_len + 0xf) & ~0xf)) == NULL)
                err("Failed to allocate memory for the ciphertext\n");

        if (wc_RNG_GenerateBlock(&rng, *iv, *iv_len) != 0)
                err("Failed to gernate random IV\n");

        if (wc_AesGcmSetKey(&aes, (const uint8_t *)skey, skey_len) != 0)
                err("Failed to set AES-GCM key\n");

        if (wc_AesGcmEncrypt(&aes, *ciphertext, plaintext, plaintext_len,
                             *iv, *iv_len, *tag, *tag_len, aad, aad_len) != 0)
                err("Failed to encrypt data with AES-GCM\n");

        wc_AesFree(&aes);

        return 0;
}

/* Decrypt ciphertext data using 256b AES-GCM. */
int aes_gcm_256b_decrypt(uint8_t   *ciphertext,
                         uint32_t   ciphertext_len,
                         uint8_t   *skey,
                         uint32_t   skey_len,
                         uint8_t   *aad,
                         uint32_t   aad_len,
                         uint8_t   *iv,
                         uint32_t   iv_len,
                         uint8_t   *tag,
                         uint32_t   tag_len,
                         uint8_t  **plaintext,     // out (must free)
                         uint32_t  *plaintext_len) // out
{
        Aes aes;

        wc_AesInit(&aes, NULL, 0);

        /* Allocate a buffer for the plaintext. */
        *plaintext_len = ciphertext_len;
        if ((*plaintext = malloc(*plaintext_len)) == NULL)
                err("Failed to allocate memory for the plaintext\n");

        if (wc_AesGcmSetKey(&aes, (const uint8_t *)skey, skey_len) != 0)
                err("Failed to set AES-GCM key\n");

        if (wc_AesGcmDecrypt(&aes, *plaintext, ciphertext, ciphertext_len,
                             iv, iv_len, tag, tag_len, aad, aad_len) != 0)
                err("Failed to decrypt data with AES-GCM\n");

        wc_AesFree(&aes);

        return 0;
}

int ecies_receiver_load_key(char      *filename,
                            ecc_key   *ec_key,    // out
                            int       *curve,     // out
                            uint8_t  **pubk,      // out (must free)
                            uint32_t  *pubk_len,  // out
                            uint8_t  **privk,     // out (must free)
                            uint32_t  *privk_len) // out
{
        uint8_t   buf[4096];
        uint32_t  buf_len;
        uint32_t  idx;
        FILE     *file;

        wc_ecc_init(ec_key);

        if ((file = fopen(filename, "rb")) == NULL)
                err("Failed to read private EC key file '%s'\n", filename);

        buf_len = fread(buf, 1, sizeof(buf), file);
        fclose(file);

        idx = 0;
        if (wc_EccPrivateKeyDecode(buf, &idx, ec_key, buf_len) != 0)
                err("Failed to parse private EC key file '%s'\n", filename);

        *curve = (ec_key->idx == -1) ? ec_key->dp->id :
                                       wc_ecc_get_curve_id(ec_key->idx);
        log("%-10s: %s(%d)\n", "curve", wc_ecc_get_name(*curve), *curve);

        /* Get the EC key's public key in a binary array format. */
        ec_key_public_key_to_bin(ec_key, pubk, pubk_len);

        /* Get the EC key's private key in a binary array format. */
        ec_key_private_key_to_bin(ec_key, privk, privk_len);

        log("**********************************************\n"
            "*  (ECIES RECEIVER) EC KEY LOADED FROM FILE  *\n"
            "**********************************************\n");
        dump_hex("pubkey", *pubk, *pubk_len);
        dump_hex("privkey", *privk, *privk_len);

        log("%-10s: %s(%d)\n", "curve", wc_ecc_get_name(*curve), *curve);

        return 0;
}

int ecies_transmitter_send_message(uint8_t        *msg,
                                   uint32_t        msg_len,
                                   int             curve,
                                   const uint8_t  *peer_pubk,
                                   const uint8_t   peer_pubk_len,
                                   uint8_t       **epubk,          // out (must free)
                                   uint32_t       *epubk_len,      // out
                                   uint8_t       **iv,             // out (must free)
                                   uint8_t        *iv_len,         // out
                                   uint8_t       **tag,            // out (must free)
                                   uint8_t        *tag_len,        // out
                                   uint8_t       **ciphertext,     // out (must free)
                                   uint8_t        *ciphertext_len) // out
{
        uint8_t  *skey      = NULL; // DH generated shared symmetric key
        uint32_t  skey_len  = 0;

        /* Generate the shared symmetric key (transmitter). */
        ecies_transmitter_generate_symkey(curve, peer_pubk, peer_pubk_len,
                                          epubk, epubk_len, &skey, &skey_len);
        if (skey_len != 32)
                err("Invalid symkey length %db (expecting 256b)\n",
                    (skey_len * 8));

        log("*******************************************************************\n"
            "*  (ECIES TRANSMITTER) EPHEMERAL EC PUBLIC KEY AND SYMMETRIC KEY  *\n"
            "*******************************************************************\n");
        dump_hex("epubkey", *epubk, *epubk_len);
        dump_hex("symkey", skey, skey_len);

        /* Encrypt the data using 256b AES-GCM. */
        aes_gcm_256b_encrypt(msg, msg_len, skey, skey_len, NULL, 0,
                             iv, iv_len, tag, tag_len,
                             ciphertext, ciphertext_len);

        log("************************************************\n"
            "*  (ECIES TRANSMITTER) AES-GCM ENCRYPTED DATA  *\n"
            "************************************************\n");
        log("%-10s: (%d) %s\n", "plain-tx", msg_len, msg); // it's a string
        dump_hex("iv", *iv, *iv_len);
        dump_hex("tag", *tag, *tag_len);
        dump_hex("cipher", *ciphertext, *ciphertext_len);

        free(skey);

        return 0;
}

int ecies_receiver_recv_message(ecc_key       *ec_key,
                                int            curve,
                                const uint8_t *peer_pubk,
                                const uint8_t  peer_pubk_len,
                                uint8_t       *iv,
                                uint8_t        iv_len,
                                uint8_t       *tag,
                                uint8_t        tag_len,
                                uint8_t       *ciphertext,
                                uint8_t        ciphertext_len)
{
        // Shared symmetric encryption key (DH generated)
        uint8_t  *skey     = NULL;
        uint32_t  skey_len = 0;

        // Decrypted data (plaintext)
        uint8_t  *plaintext     = NULL;
        uint32_t  plaintext_len = 0;

        /* Generate the shared symmetric key (receiver). */
        ecies_receiver_generate_symkey(ec_key, curve,
                                       peer_pubk, peer_pubk_len,
                                       &skey, &skey_len);
        if (skey_len != 32)
                err("Invalid symkey length %db (expecting 256b)\n",
                    (skey_len * 8));

        log("************************************\n"
            "*  (ECIES RECEIVER) SYMMETRIC KEY  *\n"
            "************************************\n");
        dump_hex("symkey", skey, skey_len);

        /* Decrypt the data using 256b AES-GCM. */
        aes_gcm_256b_decrypt(ciphertext, ciphertext_len,
                             skey, skey_len, NULL, 0,
                             iv, iv_len, tag, tag_len,
                             &plaintext, &plaintext_len);

        log("*********************************************\n"
            "*  (ECIES RECEIVER) AES-GCM DECRYPTED DATA  *\n"
            "*********************************************\n");
        log("%-10s: (%d) %s\n", "plain-rx", plaintext_len, plaintext);

        free(skey);
        free(plaintext);

        return 0;
}

int main(int argc, char * argv[])
{
        ecc_key ec_key;  // EC key from key file

        // Receiver's EC Key (public, private, curve)
        uint8_t  *pubk      = NULL;
        uint32_t  pubk_len  = 0;
        uint8_t  *privk     = NULL;
        uint32_t  privk_len = 0;
        int       curve;

        // Transmitter's ephemeral public EC Key
        uint8_t  *epubk     = NULL;
        uint32_t  epubk_len = 0;

        // AES-GCM encrypted data (IV, authentication tag, ciphertext)
        uint8_t *iv             = NULL;
        uint8_t  iv_len         = 0;
        uint8_t *tag            = NULL;
        uint8_t  tag_len        = 0;
        uint8_t *ciphertext     = NULL;
        uint8_t  ciphertext_len = 0;

        /* init wolfssl */
        wolfSSL_Init();

        if (argc != 2)
                err("Must specify EC key file in DER format\n"
                    "Usage: %s <file.der>\n", argv[0]);

        /* ECIES Receiver loads the EC key. */
        ecies_receiver_load_key(argv[1], &ec_key, &curve,
                                &pubk, &pubk_len, &privk, &privk_len);

        /*
         * At this point (receiver private key data loaded):
         *   - 'ppub'  holds the public key in uncompressed binary format
         *   - 'ppriv' holds the private key in binary format
         *   - 'curve' holds the curve name in ID format
         */
        log("\n-> (receiver) sends public key, curve name...\n\n");

        /* ECIES Transmitter sends encrypted message to the Receiver. */
        #define MSG "The quick brown fox jumps over the lazy dog!"
        ecies_transmitter_send_message((uint8_t *)MSG, (strlen(MSG) + 1),
                                       curve, pubk, pubk_len,
                                       &epubk, &epubk_len,
                                       &iv, &iv_len, &tag, &tag_len,
                                       &ciphertext, &ciphertext_len);

        /*
         * At this point (transmitter encrypted messsage):
         *   - 'epubk'      holds the ephemeral public key in uncompressed
         *                  binary format, generated by the transmitter
         *   - 'iv'         holds the IV used for the AES-GCM encrypted data
         *   - 'tag'        holds the AES-GCM auth tag of the encrypted data
         *   - 'ciphertext' holds encrypted message data
         */
        log("\n-> (transmitter) sends ephemeral public key, IV, tag, ciphertxt...\n\n");

        /* ECIES Receiver receives encrypted message from the Transmitter. */
        ecies_receiver_recv_message(&ec_key, curve, epubk, epubk_len,
                                    iv, iv_len, tag, tag_len,
                                    ciphertext, ciphertext_len);

        free(iv);
        free(tag);
        free(ciphertext);
        free(epubk);
        free(pubk);
        free(privk);

        return 0;
}

