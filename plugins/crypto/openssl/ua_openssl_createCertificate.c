/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2021 (c) Christian von Arnim, ISW University of Stuttgart (for VDW and umati)
 *
 */

#include "securitypolicy_openssl_common.h"
#include "ua_openssl_version_abstraction.h"

#define RSA_KEY_SIZE 4096
#include <openssl/x509v3.h>
#include <openssl/pem.h>

int add_ext(X509 *cert, int nid, char *value);

int add_ext(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /*
     * Issuer and subject certs: both the target since it is self signed, no
     * request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

UA_StatusCode UA_CreateCertificate(UA_ByteString *derPKey, UA_ByteString *derCert)
{
    if(!derPKey || !derCert){
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    UA_ByteString_clear(derPKey);
    UA_ByteString_clear(derCert);

    UA_Int32 serial = 1;

    /// \TODO: Seed Random geenrator!!
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;

    pkey = EVP_PKEY_new();
    x509 = X509_new();
    UA_StatusCode errRet = UA_STATUSCODE_GOOD;

    if(!pkey || !x509) {
        errRet = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }

    //UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Generating RSA key. This may take a while.");
    /// \todo use new RSA_generate_key_ex with backward compatible wrapper
    rsa = RSA_generate_key(RSA_KEY_SIZE, RSA_F4, NULL, NULL);
    if(!rsa) {
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Generating RSA key failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    if(EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Assign RSA key failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
    /*RSA_free(rsa);
    rsa = NULL;*/

    // x509v3 has version 2 (https://www.openssl.org/docs/man1.1.0/man3/X509_set_version.html)
    if(X509_set_version(x509, 2) != 1) {
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Setting version failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
    
    if(ASN1_INTEGER_set(X509_get_serialNumber(x509), serial) != 1) {
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Setting serial number failed.");
        // Only memory errors are possible
        errRet = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }

    if(X509_gmtime_adj(X509_get_notBefore(x509), 0) == NULL) {
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Setting 'not before' failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    if(X509_gmtime_adj(X509_get_notAfter(x509), (UA_Int64)60*60*24*356) == NULL) {
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Setting 'not before' failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    if(X509_set_pubkey(x509, pkey) != 1) {
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Setting publik key failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    X509_NAME * name = X509_get_subject_name(x509);
    if(name == NULL) {
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Getting name failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    if(X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *) "UK", -1, -1, 0) != 1) {
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Setting name failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
    X509_NAME_add_entry_by_txt(name, "CN",
                               MBSTRING_ASC, (const unsigned char *) "OpenSSL Group", -1, -1, 0);
    /// \todo add other text parts

    if(X509_set_issuer_name(x509, name) != 1) {
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Setting name failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    add_ext(x509, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(x509, NID_key_usage, "critical,keyCertSign,cRLSign");

    add_ext(x509, NID_subject_key_identifier, "hash");
    add_ext(x509, NID_subject_alt_name, "DNS:localhost,URI:urn:open62541.server.application");

    /* Some Netscape specific extensions */
    /*add_ext(x509, NID_netscape_cert_type, "sslCA");

    add_ext(x509, NID_netscape_comment, "example comment extension");*/
    if(X509_sign(x509, pkey, EVP_sha256()) == 0) {
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Signing failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    derPKey->length = i2d_PrivateKey(pkey, &derPKey->data);
    if(derPKey->length <= 0) {
        derPKey->length = 0;
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Create private .der key failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
    BIO* bioCert = BIO_new_file("cert2.pem", "w");
    PEM_write_bio_X509(bioCert, x509);

    derCert->length = i2d_X509(x509, &derCert->data);
    if(derCert->length <= 0) {
        derCert->length = 0;
        //UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURECHANNEL, "Create Certificate: Create certificate .der failed.");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    return UA_STATUSCODE_GOOD;
cleanup:
    UA_ByteString_clear(derCert);
    UA_ByteString_clear(derPKey);
    RSA_free(rsa);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return errRet;
}
