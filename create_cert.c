#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <string.h>
#include <wchar.h>      /* For wcslen() */
#include <locale.h>

#include "libipro.h"


 // begin //
/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */
int crt_prvkey(EVP_PKEY **tpp_pkeyp, const int tc_bits)
{
    int ret = 0;
    EVP_PKEY *p_pk = NULL;
    RSA *p_rsa = NULL;

    if ( (p_pk = EVP_PKEY_new()) == NULL ) {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Create Private Key Error", __func__, __LINE__);
        ret = -1;
        goto err;
    }

    //Rand( NULL, 1, out );//Generate random number seed

    p_rsa = RSA_generate_key(tc_bits, RSA_F4, 0/*callback function*/, NULL);//Generate key pair
    if (!p_rsa) {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Generate Private Key File Error", __func__, __LINE__);
        ret = -2;
        goto err;
    }

    //PEM_write_bio_RSAPrivateKey
    if ( !EVP_PKEY_assign_RSA(p_pk, p_rsa) ) {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Assign RSA Error", __func__, __LINE__);
        ret = -3;
        goto err;
    }

    *tpp_pkeyp = p_pk;
err:
    if (p_rsa != NULL)
        p_rsa = NULL;
    return ret;
}


/**
 * create private key file
 *
 * @param [in]    bits        digits
 * @param [in]    type
 * @param [in]    prvfile     private key file
 *
 * @return whether create successfully or not
 */
int create_prvkey(const int tc_bits, const int tc_type, const char *tcp_prvFile)
{
    int ret = 0;
    EVP_PKEY *p_prikey = NULL;
    BIO *p_biokey = NULL;

    if((p_biokey = BIO_new_file(tcp_prvFile, "w")) == NULL)
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Create Private Key File Error", __func__, __LINE__);
        ret = -2;
        goto end;
    }
    if(crt_prvkey(&p_prikey, tc_bits))
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Make Private Key Error", __func__, __LINE__);
        ret = -3;
        goto end;
    }

    if(tc_type == CERT_PEM)
    {
        ret = PEM_write_bio_PrivateKey(p_biokey, p_prikey, NULL, NULL, 0, NULL, NULL);
    }
    else if(tc_type == CERT_DER)
    {
        ret = i2d_PrivateKey_bio(p_biokey, p_prikey);
    }

    if(!ret)
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Save Cert or Key File Error", __func__, __LINE__);
        ret = -1;
    }
end:
    if (p_biokey != NULL)
        BIO_free(p_biokey);
    if (p_prikey != NULL)
        EVP_PKEY_free(p_prikey);

    return ret;
}


/**
 * Add the content into the certification
 *
 * @param [in]    x509name        x509 name
 * @param [in]    type
 * @param [in]    iput     the content of the input
 * @param [in]    ilen     the length of the input
 *
 * @return whether add successfully or not
 */
int Add_Name(X509_NAME *tp_x509name, const int tc_type, const char *tcp_iput,
            const int tc_ilen)
{
    ASN1_STRING stmp, *p_str = &stmp;
    int ret = 0;
    wchar_t *p_ws = NULL, wc;
    unsigned char cbuf[256] = {0};
    char input[256] = {0};
    int wslen, wcnt, i;
    strncpy(input, tcp_iput, tc_ilen);
    wslen = strlen(input) + 1;
    if(wslen == 1){
        ret = -1;
        goto end;
    }

    p_ws = malloc(sizeof(wchar_t) * wslen);
    if ((wcnt = mbstowcs(p_ws, input, wslen)) == -1)
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - mbstowcs convert error", __func__, __LINE__);
        ret = -2;
        goto end;
    }

    for(i = 0; i < (int)wcslen(p_ws); i++)
    {
        wc = p_ws[i];
        cbuf[2*i] = wc/256;
        cbuf[2*i+1] = wc%256;
    }

    ASN1_mbstring_copy(&p_str, cbuf, 2*wslen, MBSTRING_BMP, B_ASN1_UTF8STRING);
    X509_NAME_add_entry_by_NID(tp_x509name, tc_type, V_ASN1_UTF8STRING, stmp.data, stmp.length, -1, 0);

end:
    if (p_ws)
        free(p_ws);
    return ret;
}

int Add_ExtReq(STACK_OF(X509_EXTENSION) *tp_sk, const int tc_nid, char *tc_value)
{
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, tc_nid, tc_value);
    if (!ex)
        return 0;
    sk_X509_EXTENSION_push(tp_sk, ex);

    return 1;
}

int crt_req(const struct stuSUBJECT *tcp_reqInfo, X509_REQ **tpp_req, EVP_PKEY **tpp_prvkey)
{
    X509_REQ *p_req = NULL;
    X509_NAME *p_name = NULL;

    if ( (p_req = X509_REQ_new()) == NULL )
        goto err;
    //Rand( NULL, 1, out );//Generate random number seed

    X509_REQ_set_pubkey(p_req, *tpp_prvkey);

    p_name = X509_REQ_get_subject_name(p_req);

    /* This function creates and adds the entry, working out the
    * correct string type and performing checks on its length.
    * Normally we'd check the return value for errors
    */

    setlocale(LC_CTYPE, "");

    log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - add information into certificate.", __func__, __LINE__);
    Add_Name(p_name,NID_countryName,               (char *)tcp_reqInfo->C,    sizeof(tcp_reqInfo->C));
    Add_Name(p_name,NID_stateOrProvinceName,       (char *)tcp_reqInfo->ST,   sizeof(tcp_reqInfo->ST));
    Add_Name(p_name,NID_localityName,              (char *)tcp_reqInfo->L,    sizeof(tcp_reqInfo->L));
    Add_Name(p_name,NID_organizationName,          (char *)tcp_reqInfo->O,    sizeof(tcp_reqInfo->O));
    Add_Name(p_name,NID_organizationalUnitName,    (char *)tcp_reqInfo->OU,   sizeof(tcp_reqInfo->OU));
    Add_Name(p_name,NID_commonName,                (char *)tcp_reqInfo->CN,   sizeof(tcp_reqInfo->CN));
    Add_Name(p_name,NID_pkcs9_emailAddress,        (char *)tcp_reqInfo->MAIL, sizeof(tcp_reqInfo->MAIL));
    Add_Name(p_name,NID_email_protect,             (char *)tcp_reqInfo->PMAIL,sizeof(tcp_reqInfo->PMAIL));

    Add_Name(p_name,NID_title,                     (char *)tcp_reqInfo->T,    sizeof(tcp_reqInfo->T));
    Add_Name(p_name,NID_description,               (char *)tcp_reqInfo->D,    sizeof(tcp_reqInfo->D));
    Add_Name(p_name,NID_givenName,                 (char *)tcp_reqInfo->G,    sizeof(tcp_reqInfo->G));
    Add_Name(p_name,NID_initials,                  (char *)tcp_reqInfo->I,    sizeof(tcp_reqInfo->I));
    Add_Name(p_name,NID_name,                      (char *)tcp_reqInfo->NAME, sizeof(tcp_reqInfo->NAME));
    Add_Name(p_name,NID_surname,                   (char *)tcp_reqInfo->S,    sizeof(tcp_reqInfo->S));
    Add_Name(p_name,NID_dnQualifier,               (char *)tcp_reqInfo->QUAL, sizeof(tcp_reqInfo->QUAL));
    Add_Name(p_name,NID_pkcs9_unstructuredName,    (char *)tcp_reqInfo->STN,  sizeof(tcp_reqInfo->STN));
    Add_Name(p_name,NID_pkcs9_challengePassword,   (char *)tcp_reqInfo->PW,   sizeof(tcp_reqInfo->PW));
    Add_Name(p_name,NID_pkcs9_unstructuredAddress, (char *)tcp_reqInfo->ADD,  sizeof(tcp_reqInfo->ADD));


    /* Certificate requests can contain extensions, which can be used
        * to indicate the extensions the requestor would like added to
        * their certificate. CAs might ignore them however or even choke
        * if they are present.
    */

    /* For request extensions they are all packed in a single attribute.
    * We save them in a STACK and add them all at once later
    */

    /* Standard extenions */
    /*STACK_OF(X509_EXTENSION) *p_exts = sk_X509_EXTENSION_new_null();
    //main alternate name,URL:http://my.url.here/, support email  copy
    Add_ExtReq(p_exts, NID_subject_alt_name, "DNS:localhost,email:Dixell@emerson.com,RID:1.2.3.4,URI:192.168.2.22,IP:C0A80216");

    //Add custom extension
    int nid = OBJ_create("1.3.6.1.4.1.5315.100.2.5", "UserID", "User ID Number");
    X509V3_EXT_add_alias(nid, NID_netscape_comment);
    Add_ExtReq(p_exts, nid, "ID130203197703060618");
    // Now we've created the extensions we add them to the request

    X509_REQ_add_extensions(p_req, p_exts);
    sk_X509_EXTENSION_pop_free(p_exts, X509_EXTENSION_free);
    X509V3_EXT_cleanup();//cleanup the extension code if any custom extensions have been added
    */
    if (!X509_REQ_sign(p_req, *tpp_prvkey, EVP_sha1()))//Automatically fill in after signing x509_REQ(p_req) with private key
        goto err;

    *tpp_req = p_req;
    return(1);
err:
    return(0);
}

EVP_PKEY *ld_key(BIO *tcp_bio, const int tc_type, char *tcp_pass)    //DER/PEM
{
    EVP_PKEY *p_pkey = NULL;

    if (tc_type == CERT_DER)
    {
        p_pkey =d2i_PrivateKey_bio(tcp_bio, NULL);
    }
    else if (tc_type == CERT_PEM)
    {
        p_pkey =PEM_read_bio_PrivateKey(tcp_bio, NULL, NULL, tcp_pass);
    }
    else if (tc_type == CERT_P12)
    {
        PKCS12 *p_pkc12 = d2i_PKCS12_bio(tcp_bio, NULL);
        PKCS12_parse(p_pkc12, tcp_pass, &p_pkey, NULL, NULL);
        PKCS12_free(p_pkc12);
        p_pkc12 = NULL;
    }
    else
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - bad input format specified for key", __func__, __LINE__);
        goto end;
    }
end:
    if (p_pkey == NULL)
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - unable to load Private Key", __func__, __LINE__);
    return(p_pkey);
}

EVP_PKEY *load_key(const char *tcp_key, const int tc_keylen, char *tcp_pass)
{
    EVP_PKEY *p_pkey = NULL;
    BIO *p_in = NULL;

    if(tc_keylen == 0)//Import content is a disk file
    {
        if( (p_in = BIO_new_file(tcp_key, "r")) == NULL )
        {
            log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - open CA certificate file error", __func__, __LINE__);
            return NULL;
        }
    }
    else//Import content is some memory buffer
    {
        if( (p_in = BIO_new_mem_buf(tcp_key, tc_keylen)) == NULL )//read-only
        {
            log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Make Mem Bio Error", __func__, __LINE__);
            return NULL;
        }
    }

    if((p_pkey = ld_key(p_in, CERT_DER, tcp_pass)) == NULL)//if DER
    {
        BIO_reset(p_in);//If the bio is readable and writable, all data of the bio will be cleared;
                      //If the bio is read-only, the operation will simply point the pointer to
                      //the original position, and the data in it can be read again
        p_pkey = ld_key(p_in, CERT_PEM, tcp_pass);//if PEM
    }
    if (p_in != NULL)
        BIO_free(p_in);
    return p_pkey;
}
/**
 * create the certificate request file
 *
 * @param [in]    reqinfo        request information
 * @param [in]    bits           digits
 * @param [in]    type
 * @param [in]    reqfile        certificate request file
 * @param [in]    prvfile        private key file
 *
 * @return whether create successfully or not
 */
int create_req(const struct stuSUBJECT *tcp_reqInfo, const int tc_type, const char *tcp_reqFile, const char *tcp_prvFile)
{
    int ret = 0;
    X509_REQ *p_req = NULL;
    BIO *p_bioreq = NULL;

    if((p_bioreq = BIO_new_file(tcp_reqFile, "w")) == NULL)
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Create REQ File Error", __func__, __LINE__);
        ret = -1;
        goto end;
    }

    EVP_PKEY *p_prikey = load_key(tcp_prvFile, 0, NULL);
    if (p_prikey == NULL)
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Load Private Key File Error", __func__, __LINE__);
        ret = -2;
        goto end;
    }
    if(!crt_req(tcp_reqInfo, &p_req, &p_prikey))
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Make CertReq Error", __func__, __LINE__);
        ret = -3;
        goto end;
    }

    if(tc_type == CERT_PEM)
    {
        ret = PEM_write_bio_X509_REQ(p_bioreq, p_req);
    }
    else if(tc_type == CERT_DER)
    {
        ret = i2d_X509_REQ_bio(p_bioreq, p_req);
    }
    if(!ret)
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Save Cert or Key File Error", __func__, __LINE__);
        ret = -4;
    }
end:
    if (p_bioreq != NULL)
        BIO_free(p_bioreq);
    if (p_req != NULL)
        X509_REQ_free(p_req);
    if (p_prikey != NULL)
        EVP_PKEY_free(p_prikey);

    return ret;
}
// end //

int drt_prikey_pubkey_csr(const struct stuSUBJECT *tcp_reqInfo, const int tc_bits, X509_REQ **tpp_req, EVP_PKEY **tpp_prvkey, EVP_PKEY **tpp_pubkey)
{
    X509_REQ *p_req = NULL;
    EVP_PKEY *p_prik = NULL;
    EVP_PKEY *p_pubk = NULL;
    X509_NAME *p_name = NULL;

    if ( (p_prik = EVP_PKEY_new()) == NULL )    goto err;
    if ( (p_req = X509_REQ_new()) == NULL )     goto err;
    //Rand( NULL, 1, out );//Generate random number seed
    srand(time(NULL));
    RSA *rsa = RSA_generate_key(tc_bits, RSA_F4, 0/*callback function*/, NULL);//generate the private key
    //PEM_write_bio_RSAPrivateKey
    if (!EVP_PKEY_assign_RSA(p_prik, rsa))
        goto err;

    rsa = NULL;
    X509_REQ_set_pubkey(p_req, p_prik);

    if( (p_pubk = X509_REQ_get_pubkey(p_req)) == NULL )
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - error unpacking public key", __func__, __LINE__);
        goto err;
    }

    p_name = X509_REQ_get_subject_name(p_req);

    /* This function creates and adds the entry, working out the
    * correct string type and performing checks on its length.
    * Normally we'd check the return value for errors
    */

    setlocale(LC_CTYPE, "");

    //log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - add information into certificate.", __func__, __LINE__);
    Add_Name(p_name,NID_countryName,               (char *)tcp_reqInfo->C,    sizeof(tcp_reqInfo->C));
    Add_Name(p_name,NID_stateOrProvinceName,       (char *)tcp_reqInfo->ST,   sizeof(tcp_reqInfo->ST));
    Add_Name(p_name,NID_localityName,              (char *)tcp_reqInfo->L,    sizeof(tcp_reqInfo->L));
    Add_Name(p_name,NID_organizationName,          (char *)tcp_reqInfo->O,    sizeof(tcp_reqInfo->O));
    Add_Name(p_name,NID_organizationalUnitName,    (char *)tcp_reqInfo->OU,   sizeof(tcp_reqInfo->OU));
    Add_Name(p_name,NID_commonName,                (char *)tcp_reqInfo->CN,   sizeof(tcp_reqInfo->CN));
    Add_Name(p_name,NID_pkcs9_emailAddress,        (char *)tcp_reqInfo->MAIL, sizeof(tcp_reqInfo->MAIL));
    Add_Name(p_name,NID_email_protect,             (char *)tcp_reqInfo->PMAIL,sizeof(tcp_reqInfo->PMAIL));

    Add_Name(p_name,NID_title,                     (char *)tcp_reqInfo->T,    sizeof(tcp_reqInfo->T));
    Add_Name(p_name,NID_description,               (char *)tcp_reqInfo->D,    sizeof(tcp_reqInfo->D));
    Add_Name(p_name,NID_givenName,                 (char *)tcp_reqInfo->G,    sizeof(tcp_reqInfo->G));
    Add_Name(p_name,NID_initials,                  (char *)tcp_reqInfo->I,    sizeof(tcp_reqInfo->I));
    Add_Name(p_name,NID_name,                      (char *)tcp_reqInfo->NAME, sizeof(tcp_reqInfo->NAME));
    Add_Name(p_name,NID_surname,                   (char *)tcp_reqInfo->S,    sizeof(tcp_reqInfo->S));
    Add_Name(p_name,NID_dnQualifier,               (char *)tcp_reqInfo->QUAL, sizeof(tcp_reqInfo->QUAL));
    Add_Name(p_name,NID_pkcs9_unstructuredName,    (char *)tcp_reqInfo->STN,  sizeof(tcp_reqInfo->STN));
    Add_Name(p_name,NID_pkcs9_challengePassword,   (char *)tcp_reqInfo->PW,   sizeof(tcp_reqInfo->PW));
    Add_Name(p_name,NID_pkcs9_unstructuredAddress, (char *)tcp_reqInfo->ADD,  sizeof(tcp_reqInfo->ADD));


    /* Certificate requests can contain extensions, which can be used
        * to indicate the extensions the requestor would like added to
        * their certificate. CAs might ignore them however or even choke
        * if they are present.
    */

    /* For request extensions they are all packed in a single attribute.
    * We save them in a STACK and add them all at once later
    */

    /* Standard extenions */
    /*STACK_OF(X509_EXTENSION) *p_exts = sk_X509_EXTENSION_new_null();
    //main alternate name,URL:http://my.url.here/, support email  copy
    Add_ExtReq(p_exts, NID_subject_alt_name, "DNS:localhost,email:Dixell@emerson.com,RID:1.2.3.4,URI:192.168.2.22,IP:C0A80216");

    //Add custom extension
    int nid = OBJ_create("1.3.6.1.4.1.5315.100.2.5", "UserID", "User ID Number");
    X509V3_EXT_add_alias(nid, NID_netscape_comment);
    Add_ExtReq(p_exts, nid, "ID130203197703060618");
    // Now we've created the extensions we add them to the request
    log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - no config specified", __func__, __LINE__);

    X509_REQ_add_extensions(p_req, p_exts);
    sk_X509_EXTENSION_pop_free(p_exts, X509_EXTENSION_free);
    X509V3_EXT_cleanup();//cleanup the extension code if any custom extensions have been added
    */
    if (!X509_REQ_sign(p_req, p_prik, EVP_sha1()))//Automatically fill in after signing x509_REQ(p_req) with private key
        goto err;

    *tpp_req = p_req;
    *tpp_prvkey = p_prik;
    *tpp_pubkey = p_pubk;
    return(1);
err:
    return(0);
}
/**
 * create the certificate request file and private key file and public key file
 *
 * @param [in]    reqinfo        request information
 * @param [in]    bits           digits
 * @param [in]    type
 * @param [in]    reqfile        certificate request file
 * @param [in]    prifile        private key file
 * @param [in]    pubfile        public key file
 *
 * @return whether create successfully or not
 */
int direct_prikey_pubkey_csr(const struct stuSUBJECT *tcp_reqInfo, const int tc_bits, const int tc_type, const char *tcp_reqFile,
                             const char *tcp_priFile, const char *tcp_pubFile)
{
    int ret = 0;
    int i = 0, j = 0, k = 0;
    X509_REQ *p_req = NULL;
    EVP_PKEY *p_prikey = NULL;
    EVP_PKEY *p_pubkey = NULL;
    BIO *p_bioreq = NULL;
    BIO *p_bioprikey = NULL;
    BIO *p_biopubkey = NULL;

    if((p_bioreq = BIO_new_file(tcp_reqFile, "w")) == NULL)
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Create REQ File Error", __func__, __LINE__);
        ret = -1;
        goto end;
    }

   if( (tcp_priFile != NULL) && ((p_bioprikey = BIO_new_file(tcp_priFile, "w")) == NULL) )
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Create Private Key File Error", __func__, __LINE__);
        ret = -2;
        goto end;
    }

    if( (tcp_pubFile != NULL) && ((p_biopubkey = BIO_new_file(tcp_pubFile, "w")) == NULL) )
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Create Public Key File Error", __func__, __LINE__);
        ret = -3;
        goto end;
    }

    if(!drt_prikey_pubkey_csr(tcp_reqInfo, tc_bits, &p_req, &p_prikey, &p_pubkey))
    {
        log_printf(NULL, IPRO_SEV_ERROR, "%s()%d - Make CertReq Error", __func__, __LINE__);
        ret = -4;
        goto end;
    }

    if(tc_type == CERT_PEM)
    {
        i = PEM_write_bio_X509_REQ(p_bioreq, p_req);
        if(tcp_priFile != NULL)
            j = PEM_write_bio_PrivateKey(p_bioprikey, p_prikey, NULL, NULL, 0, NULL, NULL);
        else j = 1;
        if(tcp_pubFile != NULL)
            k = PEM_write_bio_PUBKEY(p_biopubkey, p_pubkey);
        else
            k = 1;
    }
    else if(tc_type == CERT_DER)
    {
        i = i2d_X509_REQ_bio(p_bioreq, p_req);
        if(tcp_priFile != NULL)
            j = i2d_PrivateKey_bio(p_bioprikey, p_prikey);
        else
            j = 1;
        if(tcp_pubFile != NULL)
            k = i2d_PUBKEY_bio(p_biopubkey, p_pubkey);
        else
            k = 1;
    }

    if(!i || !j || !k)
    {
        ret = -5;
    }
end:
    if (p_bioreq != NULL)
        BIO_free(p_bioreq);
    if (p_bioprikey != NULL)
        BIO_free(p_bioprikey);
    if (p_req != NULL)
        X509_REQ_free(p_req);
    if (p_prikey != NULL)
        EVP_PKEY_free(p_prikey);

    return ret;
}
