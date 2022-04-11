/*
 * Copyright © 2020-2021 by Academia Sinica
 *
 * This file is part of SKISSM.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SKISSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SKISSM.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef SESSION_MANAGER_H_
#define SESSION_MANAGER_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

/**
 * @brief Get an outbound session.
 * @param from From address
 * @param to To Address
 * @return Outbound session or NULL
 */
Skissm__E2eeSession *get_outbound_session(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to);

/**
 * @brief Encrypt a given plaintext. 
 * An outbound session should have be initialized already.
 * @param from From address
 * @param to To Address
 * @param plaintext plaintext to be encrypted
 * @param plaintext_len plaintext length
 * @return size_t 0 for Succcess
 */
size_t encrypt_session(
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    const uint8_t *plaintext, size_t plaintext_len
);

/**
 * @brief Create a get_pre_key_bundle_request_payload to be sent to messaging server.
 *
 * @param e2ee_address
 * @return Skissm__GetPreKeyBundleRequestPayload*
 */
Skissm__GetPreKeyBundleRequestPayload *produce_get_pre_key_bundle_request_payload(Skissm__E2eeAddress *e2ee_address);

/**
 * @brief Process an incoming get_pre_key_bundle_response_payload.
 *
 * @param from
 * @param to
 * @param get_pre_key_bundle_response_payload
 * @return size_t 0 for Succcess
 */
size_t consume_get_pre_key_bundle_response_payload(
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    Skissm__GetPreKeyBundleResponsePayload *get_pre_key_bundle_response_payload);

/**
 * @brief Create an outbound e2ee_message_payload to be sent to messaging server.
 *
 * @param outbound_session
 * @param e2ee_plaintext bytes array packed from 
 * @param e2ee_plaintext_len
 * @return Skissm__E2eeMsg*
 */
Skissm__E2eeMsg *produce_e2ee_message_payload(Skissm__E2eeSession *outbound_session, const uint8_t *e2ee_plaintext, size_t e2ee_plaintext_len);

/**
 * @brief Process an inbound e2ee_message_payload with corresponding inbound session.
 *
 * @param inbound_e2ee_message_payload
 * @return size_t 0 for Succcess
 */
size_t consume_e2ee_message_payload(Skissm__E2eeMsg *inbound_e2ee_message_payload);

Skissm__E2eeInvitePayload *produce_e2ee_invite_payload(
    Skissm__E2eeSession *outbound_session, ProtobufCBinaryData *pre_shared_key_1,
    ProtobufCBinaryData *pre_shared_key_2, ProtobufCBinaryData *pre_shared_key_3
);

size_t consume_e2ee_invite_payload(Skissm__E2eeMsg *invite_msg_payload);

Skissm__E2eeAcceptPayload *produce_e2ee_accept_payload(uint32_t cipher_suite_id, ProtobufCBinaryData *ciphertext_1);

size_t consume_e2ee_accept_payload(Skissm__E2eeMsg *accept_msg_payload);

Skissm__E2eeMsg *produce_invite_message_payload(Skissm__E2eeSession *outbound_session, Skissm__E2eeInvitePayload *e2ee_invite_payload);

Skissm__E2eeMsg *produce_accept_message_payload(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to, Skissm__E2eeAcceptPayload *e2ee_accept_payload);

#ifdef __cplusplus
}
#endif

#endif /* SESSION_MANAGER_H_ */
