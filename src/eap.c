/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "eap.h"
#include "endian-shim.h"
#include "srp.h"
#include "crypto/crypto-private.h"
#include "rist-private.h"
#include "udp-private.h"
#include "log-private.h"

#include <mbedtls/bignum.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#define HASH_ALGO SRP_SHA256
#define DIGEST_LENGTH SHA256_DIGEST_LENGTH
#define EAP_LOG_PREFIX "[EAP-SRP] "
#define EAP_AUTH_RETRY_MAX 3
#define EAP_AUTH_TIMEOUT_RETRY_MAX 5
#define EAP_AUTH_TIMEOUT 500//ms
#define EAP_REAUTH_PERIOD 3000 // ms

void eap_reset_data(struct eapsrp_ctx *ctx)
{
	if (ctx->role == EAP_ROLE_AUTHENTICATOR)
	{
		free(ctx->authenticator_bytes_salt);
		free(ctx->authenticator_bytes_verifier);
	}
	free(ctx->ascii_g);
	free(ctx->ascii_n);
	free(ctx->last_pkt);
	free(ctx->salt);
	free(ctx->verifier);
	if (ctx->srp_user)
		srp_user_delete(ctx->srp_user);
	if (ctx->srp_session)
		srp_session_delete(ctx->srp_session);
	if (ctx->srp_verifier)
		srp_verifier_delete(ctx->srp_verifier);
	ctx->ascii_g = NULL;
	ctx->ascii_n = NULL;
	ctx->last_pkt = NULL;
	ctx->salt = NULL;
	ctx->salt_len = 0;
	ctx->verifier = NULL;
	ctx->srp_user = NULL;
	ctx->srp_session = NULL;
	ctx->srp_verifier = NULL;
	ctx->authenticator_bytes_salt = NULL;
	ctx->authenticator_bytes_verifier = NULL;
}

static int send_eapol_pkt(struct eapsrp_ctx *ctx, uint8_t eapoltype, uint8_t eapcode, uint8_t identifier, size_t payload_len, uint8_t buf[])
{
	size_t offset = 0;
	struct rist_gre_hdr *gre = (struct rist_gre_hdr *)&buf[offset];
	offset += sizeof(*gre);
	struct eapol_hdr *eapol_hdr = (struct eapol_hdr *)&buf[offset];
	offset += sizeof(*eapol_hdr);
	struct eap_hdr *eap_hdr = (struct eap_hdr *)&buf[offset];
	offset += sizeof(*eap_hdr);
	memset(gre, 0, sizeof(*gre));
	gre->prot_type = htobe16(RIST_GRE_PROTOCOL_TYPE_EAPOL);
	eapol_hdr->eapversion = 2;
	eapol_hdr->eaptype = eapoltype;
	eap_hdr->code = eapcode;
	eap_hdr->identifier = identifier;
	eapol_hdr->length = eap_hdr->length = htobe16(payload_len + sizeof(*eap_hdr));

	//Store last pkt so we can retransmit it if needed
	if (identifier == ctx->last_identifier)
	{
		free(ctx->last_pkt);
		ctx->last_pkt = malloc((payload_len + EAPOL_EAP_HDRS_OFFSET));
		memcpy(ctx->last_pkt, buf,(payload_len + EAPOL_EAP_HDRS_OFFSET));
		ctx->last_pkt_size = (payload_len + EAPOL_EAP_HDRS_OFFSET);
		ctx->last_timestamp = timestampNTP_u64();
		ctx->timeout_retries = 0;
	}

	ssize_t bytes = sendto(ctx->peer->sd, (const char *)buf, (EAPOL_EAP_HDRS_OFFSET + payload_len), 0, &ctx->peer->u.address, ctx->peer->address_len);
	if (bytes != (ssize_t)(offset + payload_len))
	{
		//sockerr
		return -1;
	}
	return 0;
}


//EAP REQUEST HANDLING
static int process_eap_request_identity(struct eapsrp_ctx *ctx, uint8_t identifier)
{
	eap_reset_data(ctx);
	uint8_t eapolpkt[512];
	size_t offset = EAPOL_EAP_HDRS_OFFSET;
	eapolpkt[offset] = EAP_TYPE_IDENTITY;
	offset += 1;
	memcpy(&eapolpkt[offset], ctx->username, strlen(ctx->username));
	offset += strlen(ctx->username);
	size_t len = offset;
	len -= EAPOL_EAP_HDRS_OFFSET;
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, len, eapolpkt);
}

static int process_eap_request_srp_challenge(struct eapsrp_ctx *ctx, uint8_t identifier, size_t len, uint8_t pkt[])
{
	if (len < 6)
		return EAP_LENERR;
	size_t offset = 0;
	uint16_t *tmp_swap = (uint16_t *)&pkt[offset];
	size_t name_len = be16toh(*tmp_swap);
	offset += 2;
	//name can be ignored
	offset += name_len;
	if (offset > len)
		return EAP_LENERR;
	tmp_swap = (uint16_t *)&pkt[offset];
	size_t salt_len = be16toh(*tmp_swap);
	offset += 2;
	if (len < (offset + salt_len))
		return EAP_LENERR;
	if (salt_len > ctx->salt_len)
		ctx->salt = realloc(ctx->salt, salt_len);
	memcpy(ctx->salt, &pkt[offset], salt_len);
	ctx->salt_len = salt_len;
	offset += salt_len;
	tmp_swap = (uint16_t *)&pkt[offset];
	size_t generator_len = be16toh(*tmp_swap);
	offset += 2;
	if (generator_len != 0)
	{
		if (len < (offset + generator_len))
			return EAP_LENERR;
		mbedtls_mpi tmp;
		mbedtls_mpi_init(&tmp);
		mbedtls_mpi_read_binary(&tmp, (const unsigned char *)&pkt[offset], generator_len);
		char generator[16];
		char *generator_buf = generator;
		size_t olen = 0;
		int ret = 0;
		if ((ret = mbedtls_mpi_write_string(&tmp, 16, generator, 16, &olen)) !=0)
		{
			if (ret == MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL)
			{
				generator_buf = malloc(olen);
				mbedtls_mpi_write_string(&tmp, 16, generator_buf, olen, &olen);
			} else
				return ret;
		}
		offset += generator_len;
		size_t remaining_bytes = len - offset;
		mbedtls_mpi_read_binary(&tmp, (const unsigned char *)&pkt[offset], remaining_bytes);
		olen = 0;
		char *n_modulus = NULL;
		mbedtls_mpi_write_string(&tmp, 16, n_modulus, 0, &olen);
		n_modulus = malloc(olen);
		mbedtls_mpi_write_string(&tmp, 16, n_modulus, olen, &olen);
		mbedtls_mpi_free(&tmp);
		if (ctx->srp_session)
			srp_session_delete(ctx->srp_session);
		ctx->srp_session = srp_session_new(HASH_ALGO, SRP_NG_CUSTOM, n_modulus, generator_buf);
		free(n_modulus);
		if (generator_buf != generator)
			free(generator_buf);
	} else {
		if (ctx->srp_session)
			srp_session_delete(ctx->srp_session);
		ctx->srp_session = srp_session_new(HASH_ALGO, SRP_NG_2048, NULL, NULL);
	}
	if (ctx->srp_user)
		srp_user_delete(ctx->srp_user);
	ctx->srp_user = srp_user_new(ctx->srp_session, ctx->username, (const unsigned char*)ctx->password, strlen(ctx->password));
	size_t len_A;
	char * bytes_A;
	char * username;
	srp_user_start_authentication(ctx->srp_user, (const char **)&username, (const unsigned char **)&bytes_A, &len_A);
	uint8_t *response = malloc(EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr) + len_A);
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&response[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_CHALLENGE;
	memcpy(&response[EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr)], bytes_A, len_A);
	int ret = send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, (len_A + sizeof(*hdr)), response);
	free(response);
	return ret;
}

static int process_eap_request_srp_server_key(struct eapsrp_ctx *ctx, uint8_t identifier, size_t len, uint8_t pkt[])
{
	char *bytes_B = (char *)pkt;
	size_t len_B = len;
	size_t len_M = 0;
	char *bytes_M;
	srp_user_process_challenge(ctx->srp_user, (const unsigned char *)ctx->salt, ctx->salt_len,(const unsigned char *) bytes_B, len_B, (const unsigned char**)&bytes_M, &len_M);
	if (!bytes_M)
	{
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		//"must disconnect immediately, set tries past limit"
		ctx->tries = 255;
		return -255;
	}
	assert(len_M == DIGEST_LENGTH);
	size_t out_len = sizeof(struct eap_srp_hdr) + 4 + DIGEST_LENGTH;
	uint8_t response[(EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr) + 4 + DIGEST_LENGTH)];
	size_t offset = EAPOL_EAP_HDRS_OFFSET;
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&response[offset];
	offset += sizeof(*hdr);
	memset(&response[offset], 0, 4);
	offset += 4;
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_SERVER_KEY;
	memcpy(&response[offset], bytes_M, len_M);
	int ret = send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, out_len, response);
	return ret;
}

static int process_eap_request_srp_server_validator(struct eapsrp_ctx *ctx, uint8_t identifier, size_t len, uint8_t pkt[])
{
	if (len < (4 + DIGEST_LENGTH))
		return EAP_LENERR;
	srp_user_verify_session(ctx->srp_user, &pkt[4]);
	if (srp_user_is_authenticated(ctx->srp_user))
	{
		if (ctx->authentication_state < EAP_AUTH_STATE_SUCCESS)
			rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"Succesfully authenticated\n");
		ctx->authentication_state = EAP_AUTH_STATE_SUCCESS;
		ctx->last_auth_timestamp = timestampNTP_u64();
		ctx->tries = 0;
		uint8_t outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr))];
		struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
		hdr->type = EAP_TYPE_SRP_SHA1;
		hdr->subtype = EAP_SRP_SUBTYPE_SERVER_VALIDATOR;
		return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, sizeof(hdr), outpkt);
	}
	//perm failure
	ctx->authentication_state = EAP_AUTH_STATE_FAILED;
	ctx->tries = 255;

	return -1;
}

static int process_eap_request(struct eapsrp_ctx *ctx, uint8_t pkt[], size_t len, uint8_t identifier)
{
	uint8_t type = pkt[0];
	if (type == EAP_TYPE_IDENTITY)
		return process_eap_request_identity(ctx, identifier);
	if (type == EAP_TYPE_SRP_SHA1)
	{
		uint8_t subtype = pkt[1];
		switch (subtype)
		{
			case EAP_SRP_SUBTYPE_CHALLENGE:
				return process_eap_request_srp_challenge(ctx, identifier, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SUBTYPE_SERVER_KEY:
				return process_eap_request_srp_server_key(ctx, identifier, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SUBTYPE_SERVER_VALIDATOR:
				return process_eap_request_srp_server_validator(ctx, identifier, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SUBTYPE_LWRECHALLENGE:
				//handle SRP lw rechallenge
				break;
			default:
				return EAP_SRP_WRONGSUBTYPE;
		}
	}
	return -1;
}

//EAP RESPONSE HANDLING

static int process_eap_response_identity(struct eapsrp_ctx *ctx, size_t len, uint8_t pkt[])
{
	if (len > 255)
		return -1;
	memcpy(ctx->username, pkt, len);
	ctx->username[len] = '\0';
	char *bytes_v = NULL;
	size_t len_v = 0;
	char *bytes_s = NULL;
	size_t len_s = 0;
	bool std_2048_ng = false;
	char *ascii_n = NULL;
	char *ascii_g = NULL;
	ctx->lookup_func(ctx->username, &len_v, &bytes_v, &len_s, &bytes_s, &std_2048_ng, &ascii_n, &ascii_g, ctx->lookup_func_userdata);
	bool found = (len_v != 0 && bytes_v && len_s != 0 && bytes_s);
	uint8_t outpkt[1500] = { 0 };//TUNE THIS
	size_t offset = EAPOL_EAP_HDRS_OFFSET;
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[offset];
	offset += sizeof(*hdr);
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_CHALLENGE;
	if (found)
	{
		ctx->salt = malloc(len_s);
		memcpy(ctx->salt, bytes_s, len_s);
		ctx->verifier = malloc(len_v);
		memcpy(ctx->verifier, bytes_v, len_v);
		ctx->salt_len = len_s;
		ctx->verifier_len = len_v;
		memset(&pkt[offset], 0, 2);
		offset += 2;//we dont send the server name
		uint16_t *tmp_swap = (uint16_t *)&outpkt[offset];
		*tmp_swap = htobe16(len_s);
		offset += 2;
		memcpy(&outpkt[offset], bytes_s, len_s);
		offset += len_s;
		if (std_2048_ng)
		{
			if (ctx->srp_session)
				srp_session_delete(ctx->srp_session);
			ctx->srp_session = srp_session_new(HASH_ALGO, SRP_NG_2048, NULL, NULL);
			memset(&outpkt[offset], 0, 2);
			offset += 2;
		} else {
			mbedtls_mpi tmp;
			mbedtls_mpi_init(&tmp);
			mbedtls_mpi_read_string(&tmp, 16, ascii_g);
			tmp_swap = (uint16_t *)&outpkt[offset];
			*tmp_swap = htobe16((uint16_t)mbedtls_mpi_size(&tmp));
			mbedtls_mpi_write_binary(&tmp, &outpkt[offset], (1500 - offset));
			offset += mbedtls_mpi_size(&tmp);
			mbedtls_mpi_read_string(&tmp, 16, ascii_n);
			tmp_swap = (uint16_t *)&outpkt[offset];
			*tmp_swap = htobe16((uint16_t)mbedtls_mpi_size(&tmp));
			mbedtls_mpi_write_binary(&tmp, &outpkt[offset], (1500 - offset));
			if (ctx->srp_session)
				srp_session_delete(ctx->srp_session);
			ctx->srp_session = srp_session_new(HASH_ALGO, SRP_NG_CUSTOM, ascii_n, ascii_g);
		}
	}
	free(bytes_v);
	free(bytes_s);
	free(ascii_g);
	free(ascii_n);
	if (!found)
		return -1;
	ctx->last_identifier++;
	size_t out_len = offset;
	out_len -= EAPOL_EAP_HDRS_OFFSET;
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->last_identifier, out_len, outpkt);
}

static int process_eap_response_client_key(struct eapsrp_ctx *ctx, size_t len, uint8_t pkt[])
{
	char *bytes_B;
	size_t len_B;
	if (ctx->srp_verifier)
		srp_verifier_delete(ctx->srp_verifier);

	ctx->srp_verifier = srp_verifier_new(ctx->srp_session, ctx->username,
										 (const unsigned char*)ctx->salt, ctx->salt_len,
										 (const unsigned char*)ctx->verifier, ctx->verifier_len,
										 pkt, len,
										 (const unsigned char **)&bytes_B, &len_B);
	if (!bytes_B)
	{
		//perm failure set tries to max
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		ctx->tries = 255;
		return -255;
	}
	uint8_t *outpkt = malloc((EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr) + len_B));
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_SERVER_KEY;
	memcpy(&outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr))], bytes_B, len_B);
	ctx->last_identifier++;
	int ret = send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->last_identifier, (sizeof(struct eap_srp_hdr) + len_B), outpkt);
	free(outpkt);
	return ret;
}

static int process_eap_response_client_validator(struct eapsrp_ctx *ctx, size_t len, uint8_t pkt[])
{
	if (len < (4 + DIGEST_LENGTH))
		return EAP_LENERR;
	char *bytes_HAMK;
	srp_verifier_verify_session(ctx->srp_verifier, &pkt[4], (const unsigned char**)&bytes_HAMK);
	if (!bytes_HAMK)
	{
		rist_log_priv2(ctx->logging_settings, RIST_LOG_WARN, EAP_LOG_PREFIX"Authentication failed for %s@%s\n", ctx->username, ctx->ip_string);
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		ctx->tries++;
		int ret = -254;
		if (ctx->tries > EAP_AUTH_RETRY_MAX) {
			rist_log_priv2(ctx->logging_settings, RIST_LOG_ERROR, EAP_LOG_PREFIX"Authentication retry count exceeded\n");
			ret = -255;
		}
		uint8_t buf[EAPOL_EAP_HDRS_OFFSET];
		send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_FAILURE, ctx->last_identifier, 0, buf);
		eap_reset_data(ctx);
		return ret;
	}
	uint8_t outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr) + 4 + DIGEST_LENGTH)];
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_SERVER_VALIDATOR;
	memcpy(&outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr) + 4)], bytes_HAMK, DIGEST_LENGTH);
	ctx->last_identifier++;
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->last_identifier, (sizeof(*hdr) + 4 + DIGEST_LENGTH), outpkt);
}

static int process_eap_response_srp_server_validator(struct eapsrp_ctx *ctx)
{
	if (srp_verifier_is_authenticated(ctx->srp_verifier))
	{
		if (ctx->authentication_state < EAP_AUTH_STATE_SUCCESS)
			rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"Succesfully authenticated %s@%s\n", ctx->username, ctx->ip_string);
		ctx->authentication_state = EAP_AUTH_STATE_SUCCESS;
		ctx->last_auth_timestamp = timestampNTP_u64();
		ctx->tries = 0;
		ctx->last_identifier++;
		uint8_t buf[EAPOL_EAP_HDRS_OFFSET];
		send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_SUCCESS, ctx->last_identifier, 0, buf);
		return 0;
	}
	return 0;
}

static int process_eap_response(struct eapsrp_ctx *ctx, uint8_t pkt[], size_t len)
{
	uint8_t type = pkt[0];
	ctx->timeout_retries = 0;
	free(ctx->last_pkt);
	ctx->last_pkt_size = 0;
	ctx->last_pkt = NULL;
	if (type == EAP_TYPE_IDENTITY)
		return process_eap_response_identity(ctx, (len -1), &pkt[1]);
	if (type == EAP_TYPE_SRP_SHA1)
	{
		uint8_t subtype = pkt[1];
		switch (subtype)
		{
			case EAP_SRP_SUBTYPE_CLIENT_KEY:
				return process_eap_response_client_key(ctx, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SYPTYPE_CLIENT_VALIDATOR:
				return process_eap_response_client_validator(ctx, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SUBTYPE_SERVER_VALIDATOR:
				return process_eap_response_srp_server_validator(ctx);
				break;
			case EAP_SRP_SUBTYPE_LWRECHALLENGE:
				//handle SRP lw rechallenge
				break;
			default:
				return EAP_SRP_WRONGSUBTYPE;
		}
	}
	return -1;
}

static int process_eap_pkt(struct eapsrp_ctx *ctx, uint8_t pkt[], size_t len)
{
	if (ctx == NULL)
		return -1;
	if (ctx->authentication_state == EAP_AUTH_STATE_FAILED && ctx->tries >EAP_AUTH_RETRY_MAX)
		return -255;
	struct eap_hdr *hdr = (struct eap_hdr *)pkt;
	uint8_t code = hdr->code;
	uint8_t identifier = hdr->identifier;
	uint16_t length = be16toh(hdr->length);
	if (length != len)
		return EAP_LENERR;
	if (code == EAP_CODE_RESPONSE && identifier != ctx->last_identifier)
		return EAP_WRONGIDENTIFIER;
	if ((ctx->role == EAP_ROLE_AUTHENTICATEE && code == EAP_CODE_RESPONSE) ||
		(ctx->role == EAP_ROLE_AUTHENTICATOR && code == EAP_CODE_REQUEST))
		return code == EAP_CODE_RESPONSE? EAP_UNEXPECTEDRESPONSE : EAP_UNEXPECTEDREQUEST;
	switch (code)
	{
		case EAP_CODE_REQUEST:
			return process_eap_request(ctx, &pkt[sizeof(*hdr)], (len - sizeof(*hdr)), identifier);
			break;
		case EAP_CODE_RESPONSE:
			return process_eap_response(ctx, &pkt[sizeof(*hdr)], (len - sizeof(*hdr)));
			break;
		case EAP_CODE_SUCCESS:
			//handle eap success
			return 0;
			break;
		case EAP_CODE_FAILURE:
			eap_reset_data(ctx);
			rist_log_priv2(ctx->logging_settings, RIST_LOG_ERROR, EAP_LOG_PREFIX"Authentication failed\n");
			return eap_start(ctx);//try to restart the process
		default:
			return -1;
	}
	return -1;
}

int eap_request_identity(struct eapsrp_ctx *ctx)
{
	uint8_t outpkt[EAPOL_EAP_HDRS_OFFSET +1];
	outpkt[EAPOL_EAP_HDRS_OFFSET] = EAP_TYPE_IDENTITY;
	ctx->last_identifier = (uint8_t)(prand_u32() >> 24);
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->last_identifier, 1, outpkt);
}

int eap_start(struct eapsrp_ctx *ctx)
{
	uint8_t outpkt[sizeof(struct rist_gre_hdr) + sizeof(struct eapol_hdr)] = { 0 };
	struct rist_gre_hdr *gre = (struct rist_gre_hdr *)outpkt;
	gre->prot_type = htobe16(RIST_GRE_PROTOCOL_TYPE_EAPOL);
	struct eapol_hdr *eapol = (struct eapol_hdr *)&outpkt[sizeof(*gre)];
	eapol->eapversion = 2;
	eapol->eaptype = EAPOL_TYPE_START;
	sendto(ctx->peer->sd, (const char *)outpkt, (sizeof(*gre) + sizeof(*eapol)), 0, &ctx->peer->u.address, ctx->peer->address_len);
	//CHECK
	return 0;
}

void eap_set_ip_string(struct eapsrp_ctx *ctx, char ip_string[])
{
	if (ctx != NULL)
		memcpy(ctx->ip_string, ip_string, 46);
}

int eap_clone_ctx(struct eapsrp_ctx *in, struct rist_peer *peer)
{
	if (in == NULL)
		return 0;
	if (peer->eap_ctx != NULL)
		return -1;
	struct eapsrp_ctx *ctx = calloc(sizeof(*ctx), 1);
	if (!ctx)
		return -1;
	ctx->role = in->role;
	peer->eap_ctx = ctx;
	ctx->peer = peer;
	ctx->logging_settings = in->logging_settings;
	if (ctx->role == EAP_ROLE_AUTHENTICATOR)
	{
		ctx->authenticator_bytes_salt = malloc(1024);
		ctx->authenticator_bytes_verifier = malloc(1024);
		ctx->lookup_func = in->lookup_func;
		ctx->lookup_func_userdata = in->lookup_func_userdata;
		strcpy(ctx->authenticator_username, in->authenticator_username);
		if (in->authenticator_len_verifier >0 && in->authenticator_bytes_verifier != NULL)
			memcpy(ctx->authenticator_bytes_verifier, in->authenticator_bytes_verifier, in->authenticator_len_verifier);
		if (in->authenticator_len_salt > 0 && in->authenticator_bytes_salt != NULL)
			memcpy(ctx->authenticator_bytes_salt, in->authenticator_bytes_salt, in->authenticator_len_salt);
		ctx->authenticator_len_salt = in->authenticator_len_salt;
		ctx->authenticator_len_verifier = in->authenticator_len_verifier;
		if (!ctx->last_pkt)
			eap_request_identity(ctx);//immediately request identity
		return 0;
	}
	//I don't think we will ever hit this bit of code, since we will only be cloning when we are listening = authenticator
	strcpy(ctx->username, in->username);
	strcpy(ctx->password, in->password);

	return 0;
}

void eap_delete_ctx(struct eapsrp_ctx **in)
{
	if (*in == NULL)
		return;

	struct eapsrp_ctx *ctx = *in;
	eap_reset_data(ctx);

	free(ctx);
	*in = NULL;
}

int eap_process_eapol(struct eapsrp_ctx* ctx, uint8_t pkt[], size_t len)
{
	assert(ctx != NULL);
	struct eapol_hdr *hdr = (struct eapol_hdr *)pkt;
	size_t body_len = be16toh(hdr->length);
	if ((body_len +4) < (len))
		return EAP_LENERR;
	switch (hdr->eaptype)
	{
		case EAPOL_TYPE_EAP:
			return process_eap_pkt(ctx, &pkt[sizeof(*hdr)], body_len);
			break;
		case EAPOL_TYPE_START:
			if (ctx->role == EAP_ROLE_AUTHENTICATOR && !ctx->last_pkt)
				return eap_request_identity(ctx);
			return 0;
			break;
		case EAPOL_TYPE_LOGOFF:
			ctx->authentication_state = EAP_AUTH_STATE_UNAUTH;
			break;
		default:
			break;
	}
	return -1;
}

bool eap_is_authenticated(struct eapsrp_ctx *ctx)
{
	if (ctx == NULL)
		return true;
	return (ctx->authentication_state >= EAP_AUTH_STATE_SUCCESS);
}

void eap_periodic(struct eapsrp_ctx *ctx)
{
	if (ctx == NULL)
		return;
	uint64_t now = timestampNTP_u64();
	uint64_t retry_period = EAP_AUTH_TIMEOUT * RIST_CLOCK;
	uint64_t reauth_period = EAP_REAUTH_PERIOD * RIST_CLOCK;//3 seconds

	if (ctx->role == EAP_ROLE_AUTHENTICATOR && ctx->authentication_state != 1 && ctx->last_timestamp + retry_period < now &&
		ctx->timeout_retries < EAP_AUTH_TIMEOUT_RETRY_MAX && ctx->tries <= EAP_AUTH_RETRY_MAX)
	{
		if (ctx->last_pkt)
		{
			sendto(ctx->peer->sd, (const char *)ctx->last_pkt, ctx->last_pkt_size, 0, &ctx->peer->u.address, ctx->peer->address_len);
			//check
			ctx->timeout_retries++;
			ctx->last_timestamp = now;
			return;
		} else {
			eap_request_identity(ctx);
			return;
		}
	} else if (ctx->role == EAP_ROLE_AUTHENTICATOR && ctx->authentication_state == EAP_AUTH_STATE_SUCCESS &&
	           now > ctx->last_auth_timestamp + reauth_period) {
		ctx->authentication_state = EAP_AUTH_STATE_REAUTH;
		eap_request_identity(ctx);
		return;
	}
	else if (ctx->role == EAP_ROLE_AUTHENTICATEE && ctx->authentication_state ==  EAP_AUTH_STATE_SUCCESS &&
			 now > ctx->last_auth_timestamp + reauth_period) {
		ctx->authentication_state = EAP_AUTH_STATE_REAUTH;
		eap_start(ctx);
		return;
	}
	uint64_t reauth_time_out = ctx->last_auth_timestamp + reauth_period + EAP_AUTH_RETRY_MAX * retry_period;
	if (ctx->authentication_state == EAP_AUTH_STATE_REAUTH && now > reauth_time_out) {
		ctx->authentication_state = EAP_AUTH_STATE_UNAUTH;
		return;
	}


}

static void internal_user_verifier_lookup(char * username,
							size_t *verifier_len, char **verifier,
							size_t *salt_len, char **salt,
							bool *use_default_2048_bit_n_modulus,
							char **n_modulus_ascii,
							char **generator_ascii,
							void *user_data)
{
	(void)n_modulus_ascii;
	(void)generator_ascii;
	if (user_data == NULL)
		return;

	struct eapsrp_ctx *ctx = (struct eapsrp_ctx *)user_data;

	char *decoded_verifier = malloc(1024);
	char *decoded_salt = malloc(1024);

	if (strcmp(username, ctx->authenticator_username) != 0)
		goto fail_decode;

	memcpy(decoded_verifier, ctx->authenticator_bytes_verifier, ctx->authenticator_len_verifier);
	memcpy(decoded_salt, ctx->authenticator_bytes_salt, ctx->authenticator_len_salt);

	*verifier = decoded_verifier;
	*verifier_len = ctx->authenticator_len_verifier;
	*salt = decoded_salt;
	*salt_len = ctx->authenticator_len_salt;
	*use_default_2048_bit_n_modulus = true;
	goto out;

fail_decode:
	*verifier_len = 0;
	*salt_len = 0;
	free(decoded_verifier);
	free(decoded_salt);
out:
	return;
}

//PUBLIC
int rist_enable_eap_srp(struct rist_peer *peer, const char *username, const char *password, user_verifier_lookup_t lookup_func, void *userdata)
{
	if (!peer)
		return RIST_ERR_NULL_PEER;
	struct rist_common_ctx *cctx = get_cctx(peer);
	if (cctx->profile == RIST_PROFILE_SIMPLE)
		return RIST_ERR_INVALID_PROFILE;
	if (peer->listening)
	{
		struct eapsrp_ctx *ctx = calloc(sizeof(*ctx), 1);
		ctx->logging_settings = get_cctx(peer)->logging_settings;
		if (ctx == NULL)
			return RIST_ERR_MALLOC;

		if (lookup_func == NULL && username != NULL && password != NULL)
		{
			size_t u_len = strlen(username);
			size_t p_len = strlen(password);
			if (u_len == 0 || u_len > 255 || p_len == 0 || p_len > 255) {
				free(ctx);
				return RIST_ERR_INVALID_STRING_LENGTH;
			}
			lookup_func = internal_user_verifier_lookup;
			struct SRPSession * session = srp_session_new(SRP_SHA256, SRP_NG_2048, NULL, NULL);
			strcpy(ctx->authenticator_username, username);
			srp_create_salted_verification_key(session, username,
									   (const unsigned char *)password, strlen(password),
									   (const unsigned char **)&ctx->authenticator_bytes_salt, &ctx->authenticator_len_salt,
									   (const unsigned char **)&ctx->authenticator_bytes_verifier, &ctx->authenticator_len_verifier);
			srp_session_delete(session);
			userdata = (void *)ctx;
			rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"EAP Authentication enabled, role = authenticator, single user\n");
		}
		else if (lookup_func == NULL) {
			free(ctx);
			return RIST_ERR_MISSING_CALLBACK_FUNCTION;
		}
		else
			rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"EAP Authentication enabled, role = authenticator, srp file\n");
		ctx->lookup_func = lookup_func;
		ctx->lookup_func_userdata = userdata;
		ctx->role = EAP_ROLE_AUTHENTICATOR;
		peer->eap_ctx = ctx;
		struct rist_peer *child = peer->child;
		peer->eap_authentication_state = 1;
		ctx->peer = peer;
		while (child != NULL)
		{
			eap_clone_ctx(ctx, child);
			child = child->sibling_next;
		}
		return 0;
	}
	if (username == NULL || password == NULL)
		return RIST_ERR_NULL_CREDENTIALS;
	size_t u_len = strlen(username);
	size_t p_len = strlen(password);
	if (u_len == 0 || u_len > 255 || p_len == 0 || p_len > 255)
		return RIST_ERR_INVALID_STRING_LENGTH;
	struct eapsrp_ctx *ctx = calloc(sizeof(*ctx), 1);
	if (ctx == NULL)
		return RIST_ERR_MALLOC;
	ctx->peer = peer;
	ctx->logging_settings = get_cctx(peer)->logging_settings;
	ctx->role = EAP_ROLE_AUTHENTICATEE;
	strcpy(ctx->username, username);
	strcpy(ctx->password, password);
	peer->eap_ctx = ctx;
	rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"EAP Authentication enabled, role = authenticatee\n");
	eap_start(ctx);
	return 0;
}
