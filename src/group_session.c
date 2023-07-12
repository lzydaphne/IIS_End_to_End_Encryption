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
#include "skissm/group_session.h"

#include <string.h>

#include "skissm/cipher.h"
#include "skissm/e2ee_client.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/group_session_manager.h"
#include "skissm/mem_util.h"
#include "skissm/session.h"
#include "skissm/session_manager.h"

static const uint8_t CHAIN_KEY_SEED[1] = {0x02};
static const char MESSAGE_KEY_SEED[] = "MessageKeys";

//This function advances a group's chain key. It takes a cipher suite and a chain key as inputs, generates a hash using HMAC (a type of cryptographic hash function), and then overwrites the old chain key with this new hash.
void advance_group_chain_key(const cipher_suite_t *cipher_suite, ProtobufCBinaryData *chain_key, uint32_t iteration) {
    int group_shared_key_len = cipher_suite->get_crypto_param().hash_len;
    uint8_t shared_key[group_shared_key_len];
    cipher_suite->hmac(
        chain_key->data, chain_key->len,
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        shared_key
    );

    overwrite_protobuf_from_array(chain_key, shared_key);
}

void create_group_message_key(
    const cipher_suite_t *cipher_suite,
    const ProtobufCBinaryData *chain_key,
    Skissm__MsgKey *msg_key
) {
    int group_msg_key_len = cipher_suite->get_crypto_param().aead_key_len + cipher_suite->get_crypto_param().aead_iv_len;

    free_protobuf(&(msg_key->derived_key));
    msg_key->derived_key.data = (uint8_t *) malloc(sizeof(uint8_t) * group_msg_key_len);
    msg_key->derived_key.len = group_msg_key_len;

    int hash_len = cipher_suite->get_crypto_param().hash_len;
    uint8_t salt[hash_len];
    memset(salt, 0, hash_len);
    cipher_suite->hkdf(
        chain_key->data, chain_key->len,
        salt, sizeof(salt),
        (uint8_t *)MESSAGE_KEY_SEED, sizeof(MESSAGE_KEY_SEED) - 1,
        msg_key->derived_key.data, msg_key->derived_key.len
    );
}

static void pack_group_pre_key(
    Skissm__GroupPreKeyBundle *group_pre_key_bundle,
    uint8_t **group_pre_key_plaintext_data,
    size_t *group_pre_key_plaintext_data_len
) {
    Skissm__Plaintext *plaintext = (Skissm__Plaintext *)malloc(sizeof(Skissm__Plaintext));
    skissm__plaintext__init(plaintext);
    plaintext->version = strdup(E2EE_PLAINTEXT_VERSION);
    plaintext->payload_case = SKISSM__PLAINTEXT__PAYLOAD_GROUP_PRE_KEY_BUNDLE;
    plaintext->group_pre_key_bundle = group_pre_key_bundle;

    size_t len = skissm__plaintext__get_packed_size(plaintext);
    *group_pre_key_plaintext_data_len = len;
    *group_pre_key_plaintext_data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__plaintext__pack(plaintext, *group_pre_key_plaintext_data);

    // release
    // group_pre_key_payload will also be released
    skissm__plaintext__free_unpacked(plaintext, NULL);
}

/*The pack_group_pre_key_plaintext function creates a pre-key bundle for a group and packs it into a plaintext data structure for transport. A pre-key bundle is a collection of cryptographic keys used to establish secure group communication.*/
size_t pack_group_pre_key_plaintext(
    Skissm__GroupSession *outbound_group_session,
    uint8_t **group_pre_key_plaintext_data,
    char *old_session_id
) {
    Skissm__GroupPreKeyBundle *group_pre_key_bundle = (Skissm__GroupPreKeyBundle *) malloc(sizeof(Skissm__GroupPreKeyBundle));
    skissm__group_pre_key_bundle__init(group_pre_key_bundle);

    group_pre_key_bundle->version = strdup(E2EE_GROUP_PRE_KEY_VERSION);

    group_pre_key_bundle->session_id = strdup(outbound_group_session->session_id);

    if (old_session_id != NULL) {
        group_pre_key_bundle->old_session_id = strdup(old_session_id);
    }

    copy_group_info(&(group_pre_key_bundle->group_info), outbound_group_session->group_info);

    group_pre_key_bundle->sequence = outbound_group_session->sequence;
    copy_protobuf_from_protobuf(&(group_pre_key_bundle->chain_key), &(outbound_group_session->chain_key));
    copy_protobuf_from_protobuf(&(group_pre_key_bundle->signature_public_key), &(outbound_group_session->signature_public_key));

    // pack the group_pre_key_bundle
    //Calls pack_group_pre_key to serialize the group_pre_key_bundle into a byte array (group_pre_key_plaintext_data) and returns its length (group_pre_key_plaintext_data_len).
    size_t group_pre_key_plaintext_data_len;
    pack_group_pre_key(
        group_pre_key_bundle,
        group_pre_key_plaintext_data, &group_pre_key_plaintext_data_len
    );

    // release
    // group_pre_key_bundle is released in pack_group_pre_key()
//The function returns the length of the serialized pre-key bundle data.
    // done
    return group_pre_key_plaintext_data_len;
}
//NOTE:
void create_outbound_group_session(
    const char *e2ee_pack_id,//an identifier for a particular encryption/decryption suite to use
    Skissm__E2eeAddress *user_address,// the address of the user who is creating the session     
    const char *group_name,//the name of the group for which the session is being created
    Skissm__E2eeAddress *group_address,//the address of the group for which the session is being created
    Skissm__GroupMember **group_members,// an array of addresses of the group members
    size_t group_members_num,
    char *old_session_id//an id of the previous session
) {
    /*The function first fetches the account related to the user address and validates it. If the account is null, it returns an error. 
    Then, it sets up the cipher suite according to the provided e2ee_pack_id.*/
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(user_address, &account);
    if (account == NULL) {
        ssm_notify_log(BAD_ACCOUNT, "create_outbound_group_session()");
        return;
    }
    
    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;//get target cipher suite
    int sign_key_len = cipher_suite->get_crypto_param().sign_pub_key_len;//represents the length of the public key used for signing.
/*The function then creates a new GroupSession object, setting its various attributes like the version, owner, session_id, etc.
The function also generates a random chain key for the session, along with a signature public and private key pair. These are then used to generate the associated_data attribute.*/
    Skissm__GroupSession *outbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
    skissm__group_session__init(outbound_group_session);

    outbound_group_session->version = strdup(E2EE_PROTOCOL_VERSION);
    outbound_group_session->e2ee_pack_id = strdup(e2ee_pack_id);

    copy_address_from_address(&(outbound_group_session->session_owner), user_address);
    outbound_group_session->session_id = generate_uuid_str();

    outbound_group_session->group_info = (Skissm__GroupInfo *)malloc(sizeof(Skissm__GroupInfo));
    Skissm__GroupInfo *group_info = outbound_group_session->group_info;
    skissm__group_info__init(group_info);
    group_info->group_name = strdup(group_name);
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_members = group_members_num;
    copy_group_members(&(group_info->group_members), group_members, group_members_num);

    outbound_group_session->sequence = 0;

//! Generate a random chain key for the session
/*
Key Generation: It also generates a random chain key for the session, along with a signature public and private key pair. These keys are used to generate the associated_data attribute, which is authenticated but remains in plaintext for various reasons.*/
    outbound_group_session->chain_key.len = cipher_suite->get_crypto_param().hash_len;
    outbound_group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * outbound_group_session->chain_key.len);
    get_skissm_plugin()->common_handler.gen_rand(outbound_group_session->chain_key.data, outbound_group_session->chain_key.len);

//! generate signature key pair
    cipher_suite->sign_key_gen(&(outbound_group_session->signature_public_key), &(outbound_group_session->signature_private_key));

    /*The reason why the signature public key is being used in the AD is likely to tie the session's encrypted content to a specific public key, thus binding the identity of the sender (who holds the corresponding private key) to the encrypted data. This can provide assurances of data origin authentication and integrity in addition to confidentiality.*/
    
//The "Associated Data" (AD) referred to in AEAD is data that is included in the authentication, but not in the encryption. This might be data that needs to be authenticated but also needs to remain in plaintext for various reasons.
    int ad_len = 2 * sign_key_len; // The length of the associated data (AD) is being calculated. It's two times the length of the signature public key. This means that the AD will contain two instances of the signature public key.
    outbound_group_session->associated_data.len = ad_len;
    outbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
    // The first half of the AD is being set with the signature public key.
    memcpy(outbound_group_session->associated_data.data, outbound_group_session->signature_public_key.data, sign_key_len);
    // The second half of the AD is also being set with the same signature public key.
    memcpy((outbound_group_session->associated_data.data) + sign_key_len, outbound_group_session->signature_public_key.data, sign_key_len);

    get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);

    uint8_t *group_pre_key_plaintext_data = NULL;
    //! 打包。把 pre key bundle 打包成 group pre key plaintext
    /*Then a GroupPreKeyBundle message will be packed as the payload of a Plaintext type message and delivered to each group member through one-to-one  session.
    E2EE  server  then  help  forwarding  the  one-to-one message to recipient. */
    size_t group_pre_key_plaintext_data_len = pack_group_pre_key_plaintext(outbound_group_session, &group_pre_key_plaintext_data, old_session_id);

    // send the group pre-key message to the members in the group
    size_t i, j;
    for (i = 0; i < outbound_group_session->group_info->n_group_members; i++) {
        //For each member, it retrieves the user's end-to-end encryption (E2EE) address (Skissm__E2eeAddress), which consists of the member's domain and user ID.
        Skissm__E2eeAddress *group_member_address = (Skissm__E2eeAddress *)malloc(sizeof(Skissm__E2eeAddress));
        skissm__e2ee_address__init(group_member_address);
        //It then checks if there are any existing outbound sessions (outbound_sessions) for that group member. An outbound session, in this case, would likely be a communication channel or pathway set up for sending encrypted messages to that group member.
        group_member_address->domain = strdup(outbound_group_session->group_info->group_members[i]->domain);
        Skissm__PeerUser *peer_user = (Skissm__PeerUser *)malloc(sizeof(Skissm__PeerUser));
        skissm__peer_user__init(peer_user);
        peer_user->user_id = strdup(outbound_group_session->group_info->group_members[i]->user_id);
        group_member_address->peer_case = SKISSM__E2EE_ADDRESS__PEER_USER;
        group_member_address->user = peer_user;
        Skissm__Session **outbound_sessions = NULL;
        size_t outbound_sessions_num = get_skissm_plugin()->db_handler.load_outbound_sessions(
            outbound_group_session->session_owner, group_member_address->user->user_id, &outbound_sessions
        );
//!send
/*If there are outbound sessions already set up for that group member:

It checks each session (outbound_sessions[j]), and if the session is already responded to (outbound_session->responded), it directly sends the group pre-key to that session.

If the session is not yet responded to, it generates a unique identifier (pending_plaintext_id) for the group pre-key and stores it in the database. This way, the group pre-key can be sent as soon as the recipient responds.*/
        if (outbound_sessions_num > 0 && outbound_sessions != NULL) {
            for (j = 0; j < outbound_sessions_num; j++) {
                Skissm__Session *outbound_session = outbound_sessions[j];
                if (compare_address(outbound_session->to, outbound_group_session->session_owner))
                    continue;
                if (outbound_session->responded) {
                    Skissm__SendOne2oneMsgResponse *response;
                    response = send_one2one_msg_internal(outbound_session, group_pre_key_plaintext_data, group_pre_key_plaintext_data_len);
                    skissm__send_one2one_msg_response__free_unpacked(response, NULL);
                } else {
                    /** Since the other has not responded, we store the group pre-key first so that
                     *  we can send it right after receiving the other's accept message.
                     *  If  some  one-to-one  outbound is  not ready  for  sending  message,  SKISSM  will  keep  the  data  in  database,  and  the  saved “group_pre_key_plaintext”  will  be  resent  automatically  after  a  respective  AcceptMsg  has been received and successfully create the outbound session.
                     */
                    char *pending_plaintext_id = generate_uuid_str();
                    get_skissm_plugin()->db_handler.store_pending_plaintext_data(
                        outbound_session->from,
                        outbound_session->to,
                        pending_plaintext_id,
                        group_pre_key_plaintext_data,
                        group_pre_key_plaintext_data_len
                    );
                    free(pending_plaintext_id);
                }
                // release outbound_session
                skissm__session__free_unpacked(outbound_session, NULL);
            }
            // release outbound_sessions
            free_mem((void **)&outbound_sessions, sizeof(Skissm__Session *) * outbound_sessions_num);
        } else {
            /*If there are no outbound sessions for the group member, it sends an invite to the group member to establish a session. 
            The invite includes the group pre-key (which is part of group_pre_key_plaintext_data), and the member's user ID and domain, which were stored earlier.*/
            /** Since we haven't created any session, we need to create a session before sending the group pre-key. */
            Skissm__InviteResponse *response = get_pre_key_bundle_internal(
                outbound_group_session->session_owner,
                account->jwt,
                group_member_address->user->user_id, group_member_address->domain,
                NULL,
                group_pre_key_plaintext_data, group_pre_key_plaintext_data_len
            );
            // release
            skissm__invite_response__free_unpacked(response, NULL);
        }

        // release
        //At the end of each iteration, it releases the memory allocated to the E2EE address for that member (group_member_address).
        skissm__e2ee_address__free_unpacked(group_member_address, NULL);
    }

    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__group_session__free_unpacked(outbound_group_session, NULL);
}

/*An "inbound" group session generally refers to the establishment of a secure communication channel for receiving encrypted messages from a group.*/
void create_inbound_group_session(
    const char *e2ee_pack_id,
    Skissm__GroupPreKeyBundle *group_pre_key_bundle,
    Skissm__E2eeAddress *user_address
) {
    Skissm__GroupSession *inbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
    skissm__group_session__init(inbound_group_session);

    inbound_group_session->version = strdup(group_pre_key_bundle->version);
    inbound_group_session->e2ee_pack_id = strdup(e2ee_pack_id);
    copy_address_from_address(&(inbound_group_session->session_owner), user_address);
    inbound_group_session->session_id = strdup(group_pre_key_bundle->session_id);

    copy_group_info(&(inbound_group_session->group_info), group_pre_key_bundle->group_info);

    inbound_group_session->sequence = group_pre_key_bundle->sequence;
    copy_protobuf_from_protobuf(&(inbound_group_session->chain_key), &(group_pre_key_bundle->chain_key));
    copy_protobuf_from_protobuf(&(inbound_group_session->signature_public_key), &(group_pre_key_bundle->signature_public_key));

    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
    int sign_key_len = cipher_suite->get_crypto_param().sign_pub_key_len;
    int ad_len = 2 * sign_key_len;
    inbound_group_session->associated_data.len = ad_len;
    inbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
    memcpy(inbound_group_session->associated_data.data, inbound_group_session->signature_public_key.data, sign_key_len);
    memcpy((inbound_group_session->associated_data.data) + sign_key_len, inbound_group_session->signature_public_key.data, sign_key_len);

    get_skissm_plugin()->db_handler.store_group_session(inbound_group_session);

    // release
    skissm__group_session__free_unpacked(inbound_group_session, NULL);
}
