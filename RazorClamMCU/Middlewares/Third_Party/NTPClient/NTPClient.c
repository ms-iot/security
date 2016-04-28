#include <time.h>
#include <string.h>
#include "Socket.h"
#include "netdb.h"

#define NTP_DEFAULT_TIMEOUT 4000
#define NTP_PORT 123
#define NTP_CLIENT_PORT 0 //Random port
#define NTP_TIMESTAMP_DELTA 2208988800ull //Diff btw a UNIX timestamp (Starting Jan, 1st 1970) and a NTP timestamp (Starting Jan, 1st 1900)

struct NTPPacket //See RFC 4330 for Simple NTP
{
    //WARN: We are in LE! Network is BE!
    //LSb first
    unsigned mode : 3;
    unsigned vn : 3;
    unsigned li : 2;
    uint8_t stratum;
    uint8_t poll;
    uint8_t precision;
    //32 bits header
    uint32_t rootDelay;
    uint32_t rootDispersion;
    uint32_t refId;
    uint32_t refTm_s;
    uint32_t refTm_f;
    uint32_t origTm_s;
    uint32_t origTm_f;
    uint32_t rxTm_s;
    uint32_t rxTm_f;
    uint32_t txTm_s;
    uint32_t txTm_f;
} __attribute__ ((packed));

HAL_StatusTypeDef NtpGetTime(
    const char* host,
    uint32_t timeout,
    time_t* ntpTime
    )
{
    HAL_StatusTypeDef result = HAL_OK;
    struct timeval sockTimeout = {(timeout / 1000), ((timeout - ((timeout / 1000) * 1000)) * 1000)};
    fd_set fdSet = {0};
    int lSocket = -1;
    int ret = 0;
    struct sockaddr_in localHost = {0};
    struct sockaddr_in ntpHost = {0};
    struct NTPPacket pkt ={0};
    struct sockaddr from = {0};
    socklen_t fromlen = sizeof(from);

    //Create & bind socket
    if((lSocket = lwip_socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        result = HAL_ERROR;
        goto Cleanup;
    }
    localHost.sin_family = AF_INET;
    localHost.sin_port = htons(NTP_CLIENT_PORT);
    localHost.sin_addr.s_addr = INADDR_ANY;
    if ((ret = lwip_bind(lSocket, (const struct sockaddr *) &localHost, sizeof(localHost))) < 0)
    {
        result = HAL_ERROR;
        goto Cleanup;
     }

    //Prepare NTP Packet:
    pkt.li = 0; //Leap Indicator : No warning
    pkt.vn = 4; //Version Number : 4
    pkt.mode = 3; //Client mode
    pkt.stratum = 0; //Not relevant here
    pkt.poll = 0; //Not significant as well
    pkt.precision = 0; //Neither this one is

    pkt.rootDelay = 0; //Or this one
    pkt.rootDispersion = 0; //Or that one
    pkt.refId = 0; //...

    pkt.refTm_s = 0;
    pkt.origTm_s = 0;
    pkt.rxTm_s = 0;
    pkt.txTm_s = htonl( NTP_TIMESTAMP_DELTA + time(NULL) ); //WARN: We are in LE format, network byte order is BE

    pkt.refTm_f = pkt.origTm_f = pkt.rxTm_f = pkt.txTm_f = 0;

    // Resolve address with DNS
    struct hostent *host_address = lwip_gethostbyname(host);
    if (host_address == NULL)
    {
        result = HAL_ERROR;
        goto Cleanup;
    }
    ntpHost.sin_family = AF_INET;
    ntpHost.sin_port = htons(NTP_PORT);
    memcpy((char*)&ntpHost.sin_addr.s_addr, (char*)host_address->h_addr_list[0], 4);

  //Now ping the server and wait for response
    FD_ZERO(&fdSet);
    FD_SET(lSocket, &fdSet);   
    if((ret = lwip_select(FD_SETSIZE, NULL, &fdSet, NULL, &sockTimeout)) < 0)
    {
        result = HAL_ERROR;
        goto Cleanup;
    }
    if((ret = lwip_sendto(lSocket, (char*)&pkt, sizeof(struct NTPPacket), 0, (const struct sockaddr *) &ntpHost, sizeof(ntpHost))) < 0)
    {
        result = HAL_ERROR;
        goto Cleanup;
    }

  //Read response
    FD_ZERO(&fdSet);
    FD_SET(lSocket, &fdSet);
    if((ret = lwip_select(FD_SETSIZE, &fdSet, NULL, NULL, &sockTimeout)) < 0)
    {
        result = HAL_ERROR;
        goto Cleanup;
    }
    if((ret = lwip_recvfrom(lSocket, (char*)&pkt, sizeof(struct NTPPacket), 0, (struct sockaddr*) &from, &fromlen)) < 0)
    {
        result = HAL_ERROR;
        goto Cleanup;
    }

    if(ret < sizeof(struct NTPPacket))
    {
        result = HAL_ERROR;
        goto Cleanup;
    }

    if( pkt.stratum == 0)  //Kiss of death message : Not good !
    {
        result = HAL_ERROR;
        goto Cleanup;
    }

    //Correct Endianness
    pkt.refTm_s = ntohl( pkt.refTm_s );
    pkt.refTm_f = ntohl( pkt.refTm_f );
    pkt.origTm_s = ntohl( pkt.origTm_s );
    pkt.origTm_f = ntohl( pkt.origTm_f );
    pkt.rxTm_s = ntohl( pkt.rxTm_s );
    pkt.rxTm_f = ntohl( pkt.rxTm_f );
    pkt.txTm_s = ntohl( pkt.txTm_s );
    pkt.txTm_f = ntohl( pkt.txTm_f );

    //Compute offset, see RFC 4330 p.13
    uint32_t destTm_s = (NTP_TIMESTAMP_DELTA + time(NULL));
    int64_t offset = ( (int64_t)( pkt.rxTm_s - pkt.origTm_s ) + (int64_t) ( pkt.txTm_s - destTm_s ) ) / 2; //Avoid overflow

    //Return time
    *ntpTime = time(NULL) + offset;

Cleanup:
    if(lSocket != -1)
    {
        lwip_shutdown(lSocket, SHUT_RDWR);
        lwip_close(lSocket);
        lSocket = -1;
    }
    return result;
}

