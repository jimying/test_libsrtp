#include <arpa/inet.h>
#include <assert.h>
#include <srtp2/srtp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RTP_HEADER_LEN 12

#if defined __LITTLE_ENDIAN__ /* LITTLE_ENDIAN */

typedef struct {
    unsigned char cc : 4;      /* CSRC count             */
    unsigned char x : 1;       /* header extension flag  */
    unsigned char p : 1;       /* padding flag           */
    unsigned char version : 2; /* protocol version       */
    unsigned char pt : 7;      /* payload type           */
    unsigned char m : 1;       /* marker bit             */
    uint16_t seq;              /* sequence number        */
    uint32_t ts;               /* timestamp              */
    uint32_t ssrc;             /* synchronization source */
} rtp_hdr_t;

#else /*  BIG_ENDIAN */

typedef struct {
    unsigned char version : 2; /* protocol version       */
    unsigned char p : 1;       /* padding flag           */
    unsigned char x : 1;       /* header extension flag  */
    unsigned char cc : 4;      /* CSRC count             */
    unsigned char m : 1;       /* marker bit             */
    unsigned char pt : 7;      /* payload type           */
    uint16_t seq;              /* sequence number        */
    uint32_t ts;               /* timestamp              */
    uint32_t ssrc;             /* synchronization source */
} rtp_hdr_t;

#endif

typedef struct {
    rtp_hdr_t header;
    char body[1024];
} rtp_msg_t;

int main(int argc, char **argv)
{
    srtp_err_status_t status;
    srtp_t session = NULL, session2 = NULL;
    srtp_policy_t policy;

    char key[100] = {0};
    // strcpy(key, "abc123456789012345678901234567");
    strcpy(key, "test-key");
    int ssrc = 888; // hard code

    rtp_msg_t msg;
    int msg_len = 0;

    // init
    status = srtp_init();
    assert(status == srtp_err_status_ok);
    printf("srtp init ok.\n");

    // create rtp session..
    memset(&policy, 0, sizeof(policy));
    policy.key = (uint8_t *)key;
    policy.ssrc.type = ssrc_specific;
    policy.ssrc.value = ssrc;
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
    //srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);

    status = srtp_create(&session, &policy); // create session for protect
    assert(status == srtp_err_status_ok);
    status = srtp_create(&session2, &policy); // create session for unprotect
    assert(status == srtp_err_status_ok);
    printf("srtp create success, session:%p\n", session);

    // protect
    memset(&msg, 0, sizeof(msg));
    msg_len = RTP_HEADER_LEN + strlen("hello, world") + 1;
    strcpy(msg.body, "hello, world");
    msg.header.ssrc = htonl(ssrc); // important: Must setup ssrc
    status = srtp_protect(session, &msg.header, &msg_len);
    assert(status == srtp_err_status_ok);
    printf("srtp protect success, len:%d\n", msg_len);

    // unprotect
    status = srtp_unprotect(session2, &msg.header, &msg_len);
    assert(status == srtp_err_status_ok);
    printf("srtp unprotect success, len:%d, data:%s\n", msg_len, msg.body);

    // shutdown
    srtp_dealloc(session2);
    srtp_dealloc(session);
    srtp_shutdown();
    printf("srtp shutdown..\n");
    return 0;
}

