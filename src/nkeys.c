// Copyright 2018 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "natsp.h"
#include "mem.h"
#include "util.h"
#include "tweetnacl.h"
#include "nkeys.h"

// PREFIX_BYTE_SEED is the version byte used for encoded NATS Seeds
#define PREFIX_BYTE_SEED    ((char) (18 << 3))  // Base32-encodes to 'S...'

// PREFIX_BYTE_PRIVATE is the version byte used for encoded NATS Private keys
#define PREFIX_BYTE_PRIVATE ((char) (15 << 3))  // Base32-encodes to 'P...'

// PREFIX_BYTE_SERVER is the version byte used for encoded NATS Servers
#define PREFIX_BYTE_SERVER ((char) (13 << 3))   // Base32-encodes to 'N...'

// PREFIX_BYTE_CLUSTER is the version byte used for encoded NATS Clusters
#define PREFIX_BYTE_CLUSTER ((char) (2 << 3))   // Base32-encodes to 'C...'

// PREFIX_BYTE_ACCOUNT is the version byte used for encoded NATS Accounts
#define PREFIX_BYTE_ACCOUNT ((char) 0)          // Base32-encodes to 'A...'

// PREFIX_BYTE_USER is the version byte used for encoded NATS Users
#define PREFIX_BYTE_USER    ((char) (20 << 3))  // Base32-encodes to 'U...'

static uint16_t
_getUInt16LittleEndian(char *src)
{
    char b0 = (uint16_t) src[0];
    char b1 = (uint16_t) src[1];

    return (b0 | b1<<8);
}

static bool
_isValidPublicPrefixByte(char b)
{
    switch (b)
    {
        case PREFIX_BYTE_USER:
        case PREFIX_BYTE_SERVER:
        case PREFIX_BYTE_CLUSTER:
        case PREFIX_BYTE_ACCOUNT:
            return true;
        default:
            return false;
    }
}

natsStatus
_decodeSeed(char *seed, char *raw, int rawMax, int *rawLen)
{
    natsStatus  s       = NATS_OK;
    uint16_t    crc     = 0;
    char        b1      = 0;
    char        b2      = 0;

    s = nats_Base32DecodeString(seed, raw, rawMax, rawLen);
    if (s != NATS_OK)
        return NATS_UPDATE_ERR_STACK(s);

    if (*rawLen < 4)
        return nats_setError(NATS_ERR, "%s", NKEYS_INVALID_ENCODED_KEY);

    // Read the crc that is stored as the two last bytes
    crc = _getUInt16LittleEndian((char*)(raw + (*rawLen) - 2));

    // ensure checksum is valid
    if (!nats_CRC16Validate((unsigned char*) raw, (*rawLen) - 2, crc))
        return nats_setError(NATS_ERR, "%s", NKEYS_INVALID_CHECKSUM);

    // Need to do the reverse here to get back to internal representation.
    b1 = raw[0] & 248;                          // 248 = 11111000
    b2 = (raw[0]&7)<<5 | ((raw[1] & 248) >> 3); // 7 = 00000111

    if (b1 != PREFIX_BYTE_SEED)
        return nats_setError(NATS_ERR, "%s", NKEYS_INVALID_SEED);

    if (!_isValidPublicPrefixByte(b2))
        return nats_setError(NATS_ERR, "%s", NKEYS_INVALID_PREFIX);

    return NATS_OK;
}

natsStatus
natsKeys_Sign(char *seed, char *input, char **out, int *outLen)
{
    natsStatus  s = NATS_OK;
    char        raw[2+NKEYS_SECRETKEYBYTES+2];
    int         rawLen = 0;

    *out    = NULL;
    *outLen = 0;

    memset((void*) &raw, 0, sizeof(raw));
    s = _decodeSeed(seed, (char*) &raw, (int) sizeof(raw), &rawLen);
    if (s == NATS_OK)
    {
        char *sm   = NATS_MALLOC(strlen(input) + NKEYS_BYTES + 1);
        int  smlen = 0;
        int  mlen  = (int) strlen(input);

        if (sm == NULL)
            return nats_setDefaultError(NATS_NO_MEMORY);

        s = crypto_sign((unsigned char*) sm, &smlen,
                        (const unsigned char*) input, mlen,
                        (const unsigned char*) (raw + 2));
        if (s == NATS_OK)
        {
            *out    = sm;
            *outLen = smlen - mlen;
        }
        else
            NATS_FREE(sm);
    }
    return NATS_UPDATE_ERR_STACK(s);
}
