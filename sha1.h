/*
 *  FIPS-180-1 compliant SHA-1 implementation
 *
 *  Copyright (C) 2001-2003  Christophe Devine
 *  Copyright (C) 2012       Chris Elston, Katalix Systems Ltd <celston@katalix.com>
 *
 *  Ported into Lorcon, dragorn@kismetwireless.net
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 *  Changed to use guint instead of uint 2004 by Anders Broman
 *	Original code found at http://www.cr0.net:8040/code/crypto/sha1/
 *  References: http://www.ietf.org/rfc/rfc3174.txt?number=3174
 *
 *  2012-08-21 - C Elston - Split sha1_hmac function to allow incremental usage.
 */

#ifndef _SHA1_H
#define _SHA1_H

#include <stdint.h>

/*
 * Length of a SHA-1 digest, in bytes.  160 bits = 20 bytes.
 */
#define SHA1_DIGEST_LEN 20

typedef struct
{
    uint32_t total[2];
    uint32_t state[5];
    uint8_t buffer[64];
}
sha1_context;

void sha1_starts( sha1_context *ctx );
void sha1_update( sha1_context *ctx, const uint8_t *input, uint32_t length );
void sha1_finish( sha1_context *ctx, uint8_t digest[SHA1_DIGEST_LEN] );

typedef struct {
    sha1_context ctx;
    uint8_t k_opad[64];
}
sha1_hmac_context;

void sha1_hmac_starts( sha1_hmac_context *hctx, const uint8_t *key, uint32_t keylen );
void sha1_hmac_update( sha1_hmac_context *hctx, const uint8_t *buf, uint32_t buflen );
void sha1_hmac_finish( sha1_hmac_context *hctx, uint8_t digest[SHA1_DIGEST_LEN] );
void sha1_hmac( const uint8_t *key, uint32_t keylen, const uint8_t *buf, uint32_t buflen,
                uint8_t digest[SHA1_DIGEST_LEN] );

#endif /* sha1.h */
