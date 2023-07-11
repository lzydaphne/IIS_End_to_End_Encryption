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
#ifndef SKISSM_H_
#define SKISSM_H_

#include <stdint.h>
#include <stdlib.h>

#include "skissm/AcceptMsg.pb-c.h"
#include "skissm/AcceptRequest.pb-c.h"
#include "skissm/AcceptResponse.pb-c.h"
#include "skissm/Account.pb-c.h"
#include "skissm/AddGroupMembersMsg.pb-c.h"
#include "skissm/AddGroupMembersRequest.pb-c.h"
#include "skissm/AddGroupMembersResponse.pb-c.h"
#include "skissm/ChainKey.pb-c.h"
#include "skissm/ConsumeProtoMsgRequest.pb-c.h"
#include "skissm/ConsumeProtoMsgResponse.pb-c.h"
#include "skissm/CreateGroupMsg.pb-c.h"
#include "skissm/CreateGroupRequest.pb-c.h"
#include "skissm/CreateGroupResponse.pb-c.h"
#include "skissm/E2eeAddress.pb-c.h"
#include "skissm/E2eeMsg.pb-c.h"
#include "skissm/F2fAcceptMsg.pb-c.h"
#include "skissm/F2fAcceptRequest.pb-c.h"
#include "skissm/F2fAcceptResponse.pb-c.h"
#include "skissm/F2fInviteMsg.pb-c.h"
#include "skissm/F2fInviteRequest.pb-c.h"
#include "skissm/F2fInviteResponse.pb-c.h"
#include "skissm/F2fPreKeyAcceptMsg.pb-c.h"
#include "skissm/F2fPreKeyInviteMsg.pb-c.h"
#include "skissm/GetGroupRequest.pb-c.h"
#include "skissm/GetGroupResponse.pb-c.h"
#include "skissm/GetPreKeyBundleRequest.pb-c.h"
#include "skissm/GetPreKeyBundleResponse.pb-c.h"
#include "skissm/GroupMember.pb-c.h"
#include "skissm/GroupMsgPayload.pb-c.h"
#include "skissm/GroupPreKeyBundle.pb-c.h"
#include "skissm/GroupSession.pb-c.h"
#include "skissm/IdentityKey.pb-c.h"
#include "skissm/IdentityKeyPublic.pb-c.h"
#include "skissm/InviteMsg.pb-c.h"
#include "skissm/InviteRequest.pb-c.h"
#include "skissm/InviteResponse.pb-c.h"
#include "skissm/KeyPair.pb-c.h"
#include "skissm/MsgKey.pb-c.h"
#include "skissm/NewUserDeviceMsg.pb-c.h"
#include "skissm/One2oneMsgPayload.pb-c.h"
#include "skissm/OneTimePreKey.pb-c.h"
#include "skissm/OneTimePreKeyPublic.pb-c.h"
#include "skissm/Plaintext.pb-c.h"
#include "skissm/PreKeyBundle.pb-c.h"
#include "skissm/ProtoMsg.pb-c.h"
#include "skissm/ProtoMsgTag.pb-c.h"
#include "skissm/PublishSpkRequest.pb-c.h"
#include "skissm/PublishSpkResponse.pb-c.h"
#include "skissm/Ratchet.pb-c.h"
#include "skissm/ReceiverChainNode.pb-c.h"
#include "skissm/RegisterUserRequest.pb-c.h"
#include "skissm/RegisterUserResponse.pb-c.h"
#include "skissm/RemoveGroupMembersMsg.pb-c.h"
#include "skissm/RemoveGroupMembersRequest.pb-c.h"
#include "skissm/RemoveGroupMembersResponse.pb-c.h"
#include "skissm/ResponseCode.pb-c.h"
#include "skissm/SendGroupMsgRequest.pb-c.h"
#include "skissm/SendGroupMsgResponse.pb-c.h"
#include "skissm/SendOne2oneMsgRequest.pb-c.h"
#include "skissm/SendOne2oneMsgResponse.pb-c.h"
#include "skissm/SenderChainNode.pb-c.h"
#include "skissm/Session.pb-c.h"
#include "skissm/SignedPreKey.pb-c.h"
#include "skissm/SignedPreKeyPublic.pb-c.h"
#include "skissm/SkippedMsgKeyNode.pb-c.h"
#include "skissm/SupplyOpksMsg.pb-c.h"
#include "skissm/SupplyOpksRequest.pb-c.h"
#include "skissm/SupplyOpksResponse.pb-c.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/session.h"
#include "skissm/cipher.h"
#include "skissm/log_code.h"

#define E2EE_PROTOCOL_VERSION           "E2EE_PROTOCOL_v1.0"
#define E2EE_GROUP_PRE_KEY_VERSION      "E2EE_GROUP_PRE_KEY_v1.0"
#define E2EE_PLAINTEXT_VERSION          "E2EE_PLAINTEXT_v1.0"
#define UUID_LEN                        16
#define SIGNED_PRE_KEY_EXPIRATION_MS    604800000 // 7 days
#define INVITE_WAITING_TIME_MS          60000 // 1 minute

typedef struct e2ee_pack_t {
    const char *e2ee_pack_id;
    const struct cipher_suite_t *cipher_suite;
    const struct session_suite_t *session_suite;
} e2ee_pack_t;

#define E2EE_PACK_ID_ECC_DEFAULT           "0"
#define E2EE_PACK_ID_PQC_DEFAULT           "1"

struct e2ee_pack_list_t {
  const struct e2ee_pack_t *e2ee_pack_0;
  const struct e2ee_pack_t *e2ee_pack_1;
};

typedef struct crypto_param_t {
    bool pqc_param;
    uint32_t asym_pub_key_len;
    uint32_t asym_priv_key_len;
    uint32_t kem_ciphertext_len;
    uint32_t sign_pub_key_len;
    uint32_t sign_priv_key_len;
    uint32_t sig_len;
    uint32_t hash_len;
    uint32_t aead_key_len;
    uint32_t aead_iv_len;
    uint32_t aead_tag_len;
} crypto_param_t;

typedef struct skissm_common_handler_t {
    int64_t (*gen_ts)();
    void (*gen_rand)(uint8_t *, size_t);
    void (*gen_uuid)(uint8_t uuid[UUID_LEN]);
} skissm_common_handler_t;

typedef struct skissm_db_handler_t {
    // account related handlers
    /**
     * @brief store account to db
     * @param account
     */
    void (*store_account)(Skissm__Account *);
    /**
     * @brief load account from db
     * @param account_id
     * @param account
     */
    void (*load_account)(uint64_t, Skissm__Account **);
    /**
     * @brief load account from db by giving address
     * @param address
     * @param account
     */
    void (*load_account_by_address)(Skissm__E2eeAddress *, Skissm__Account **);
    /**
     * @brief load all accounts from db
     * @param accounts
     * @return number of loaded accounts
     */
    size_t (*load_accounts)(Skissm__Account ***);
    /**
     * @brief update identity key of account to db
     * @param account_id
     * @param identity_key
     */
    void (*update_identity_key)(uint64_t, Skissm__IdentityKey *);
    /**
     * @brief update signed pre-key of account to db
     * @param account_id
     * @param signed_pre_key
     */
    void (*update_signed_pre_key)(uint64_t, Skissm__SignedPreKey *);
    /**
     * @brief load old signed pre-key by spk_id
     * @param account_id
     * @param spk_id
     * @param signed_pre_key
     */
    void (*load_signed_pre_key)(uint64_t, uint32_t, Skissm__SignedPreKey **);
    /**
     * @brief remove expired signed pre-key (keep last two) of account from db
     * @param account_id
     */
    void (*remove_expired_signed_pre_key)(uint64_t);
    /**
     * @brief update address of account to db
     * @param account_id
     * @param address
     */
    void (*update_address)(uint64_t, Skissm__E2eeAddress *);
    /**
     * @brief add an one time pre-key of account to db
     * @param account_id
     * @param one_time_pre_key
     */
    void (*add_one_time_pre_key)(uint64_t, Skissm__OneTimePreKey *);
    /**
     * @brief remove an one time pre-key of account to db
     * @param account_id
     * @param one_time_pre_key_id
     */
    void (*remove_one_time_pre_key)(uint64_t, uint32_t);
    /**
     * @brief update an one time pre-key of acount from db
     * @param account_id
     * @param one_time_pre_key_id
     */
    void (*update_one_time_pre_key)(uint64_t, uint32_t);

    // session related handlers
    /**
     * @brief find inbound session
     * @param session_id
     * @param session_owner_address
     * @param inbound_session
     */
    void (*load_inbound_session)(
        char *,
        Skissm__E2eeAddress *,
        Skissm__Session **
    );
    /**
     * @brief find the lastest outbound session
     * @param session_owner_address
     * @param to
     * @param outbound_session
     */
    void (*load_outbound_session)(
        Skissm__E2eeAddress *,
        Skissm__E2eeAddress *,
        Skissm__Session **
    );

    /**
     * @brief find the list of outbound sessions that are related to to_user_id
     * @param session_owner_address
     * @param to_user_id
     * @param outbound_sessions
     */
    size_t (*load_outbound_sessions)(
        Skissm__E2eeAddress *,
        const char *,
        Skissm__Session ***
    );

    /**
     * @brief store session
     * @param session
     */
    void (*store_session)(Skissm__Session *);
    /**
     * @brief delete old inbound session
     * @param owner
     * @param from
     * @param to
     */
    void (*unload_session)(
        Skissm__E2eeAddress *,
        Skissm__E2eeAddress *,
        Skissm__E2eeAddress *
    );

    // group session related handlers
    /**
     * @brief find outbound group session
     * @param sender_address
     * @param group_address
     * @param outbound_group_session
     */
    void (*load_outbound_group_session)(
        Skissm__E2eeAddress *,
        Skissm__E2eeAddress *,
        Skissm__GroupSession **
    );
    /**
     * @brief find inbound group session
     * @param receiver_address
     * @param session_id
     * @param inbound_group_session
     */
    void (*load_inbound_group_session)(
        Skissm__E2eeAddress *,
        char *,
        Skissm__GroupSession **
    );
    /**
     * @brief find inbound group session
     * @param receiver_address
     * @param group_address
     * @param inbound_group_sessions
     */
    size_t (*load_inbound_group_sessions)(
        Skissm__E2eeAddress *,
        Skissm__E2eeAddress *,
        Skissm__GroupSession ***
    );
    /**
     * @brief store group session
     * @param group_session
     */
    void (*store_group_session)(Skissm__GroupSession *);
    /**
     * @brief delete outbound group session
     * @param outbound_group_session
     */
    void (*unload_outbound_group_session)(Skissm__GroupSession *);
    /**
     * @brief delete old inbound group session
     * @param user_address
     * @param old_session_id
     */
    void (*unload_inbound_group_session)(Skissm__E2eeAddress *, char *);

    // pending plaintext related handlers
    /**
     * @brief store pending plaintext data
     * @param from_address
     * @param to_address
     * @param plaintext_id
     * @param plaintext_data
     * @param plaintext_data_len
     */
    void (*store_pending_plaintext_data)(
        Skissm__E2eeAddress *,
        Skissm__E2eeAddress *,
        char *, uint8_t *, size_t
    );
    /**
     * @brief load pending plaintext data
     * @param from_address
     * @param to_address
     * @param plaintext_id_list
     * @param plaintext_data_list
     * @param plaintext_data_len_list
     * @return number of loaded plaintext_data list
     */
    size_t (*load_pending_plaintext_data)(
        Skissm__E2eeAddress *,
        Skissm__E2eeAddress *,
        char ***, uint8_t ***, size_t **
    );
    /**
     * @brief delete pending plaintext data
     * @param from_address
     * @param to_address
     * @param plaintext_id
     */
    void (*unload_pending_plaintext_data)(
        Skissm__E2eeAddress *, Skissm__E2eeAddress *, char *
    );
    /**
     * @brief store pending request data
     * @param user_address
     * @param request_id
     * @param request_type
     * @param request_data
     * @param request_data_len
     */
    void (*store_pending_request_data)(
        Skissm__E2eeAddress *, char *, uint8_t, uint8_t *, size_t
    );
    /**
     * @brief load pending request data
     * @param user_address
     * @param request_id_list
     * @param request_type_list
     * @param request_data_list
     * @param request_data_len_list
     * @return number of loaded request_data list
     */
    size_t (*load_pending_request_data)(
        Skissm__E2eeAddress *, char ***, uint8_t **, uint8_t ***, size_t **
    );
    /**
     * @brief delete pending request data
     * @param user_address
     * @param request_id
     */
    void (*unload_pending_request_data)(Skissm__E2eeAddress *, char *);
} skissm_db_handler_t;

typedef struct e2ee_proto_handler_t {
    /**
     * @brief Register user
     * @param request
     * @return response
     */
    Skissm__RegisterUserResponse * (*register_user)(Skissm__RegisterUserRequest *);
    /**
     * @brief Get pre-key bundle
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__GetPreKeyBundleResponse * (*get_pre_key_bundle)(Skissm__E2eeAddress *from, const char *auth, Skissm__GetPreKeyBundleRequest *);
    /**
     * @brief Invite
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__InviteResponse * (*invite)(Skissm__E2eeAddress *from, const char *auth, Skissm__InviteRequest *);
    /**
     * @brief Accept
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__AcceptResponse * (*accept)(Skissm__E2eeAddress *from, const char *auth, Skissm__AcceptRequest *);
    /**
     * @brief Face-to-face invite
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__F2fInviteResponse * (*f2f_invite)(Skissm__E2eeAddress *from, const char *auth, Skissm__F2fInviteRequest *);
    /**
     * @brief Face-to-face accept
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__F2fAcceptResponse * (*f2f_accept)(Skissm__E2eeAddress *from, const char *auth, Skissm__F2fAcceptRequest *);
    /**
     * @brief Publish signed pre-key
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__PublishSpkResponse * (*publish_spk)(Skissm__E2eeAddress *from, const char *auth, Skissm__PublishSpkRequest *);
    /**
     * @brief Supply onetime pre-key
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__SupplyOpksResponse * (*supply_opks)(Skissm__E2eeAddress *from, const char *auth, Skissm__SupplyOpksRequest *);
    /**
     * @brief Send one2one message
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__SendOne2oneMsgResponse * (*send_one2one_msg)(Skissm__E2eeAddress *from, const char *auth, Skissm__SendOne2oneMsgRequest *);
    /**
     * @brief Create group
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__CreateGroupResponse * (*create_group)(Skissm__E2eeAddress *from, const char *auth, Skissm__CreateGroupRequest *);
    /**
     * @brief Add group members
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__AddGroupMembersResponse * (*add_group_members)(Skissm__E2eeAddress *from, const char *auth, Skissm__AddGroupMembersRequest *);
    /**
     * @brief Remove group members
     * @param request
     * @return response
     */
    Skissm__RemoveGroupMembersResponse * (*remove_group_members)(Skissm__E2eeAddress *from, const char *auth, Skissm__RemoveGroupMembersRequest *);
    /**
     * @brief Send group message
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__SendGroupMsgResponse * (*send_group_msg)(Skissm__E2eeAddress *from, const char *auth, Skissm__SendGroupMsgRequest *);
    /**
     * @brief Consume a ProtoMsg
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    Skissm__ConsumeProtoMsgResponse * (*consume_proto_msg)(Skissm__E2eeAddress *from, const char *auth, Skissm__ConsumeProtoMsgRequest *);
} e2ee_proto_handler_t;

typedef struct skissm_event_handler_t {
    /**
     * @brief notify log msg
     * @param log_code
     * @param log_msg
     */
    void (*on_log)(LogCode, const char *);
    /**
     * @brief notify user registered event
     * @param account
     */
    void (*on_user_registered)(Skissm__Account *);
    /**
     * @brief notify inbound session invited
     * @param from
     */
    void (*on_inbound_session_invited)(Skissm__E2eeAddress *);
    /**
     * @brief notify inbound session ready
     * @param inbound_session
     */
    void (*on_inbound_session_ready)(Skissm__Session *);
    /**
     * @brief notify outbound session ready
     * @param outbound_session
     */
    void (*on_outbound_session_ready)(Skissm__Session *);
    /**
     * @brief get the face-to-face password
     * @param sender_address
     * @param receiver_address
     * @param password
     * @param password_len
     */
    void (*on_f2f_password_acquired)(
        Skissm__E2eeAddress *, Skissm__E2eeAddress *,
        uint8_t **, size_t *
    );
    /**
     * @brief notify one2one msg received event
     * @param from_address
     * @param to_address
     * @param plaintext
     * @param plaintext_len
     */
    void (*on_one2one_msg_received)(
        Skissm__E2eeAddress *, Skissm__E2eeAddress *,
        uint8_t *, size_t
    );

    /**
     * @brief notify messages from other devices received event
     * @param from_address
     * @param to_address
     * @param plaintext
     * @param plaintext_len
     */
    void (*on_other_device_msg_received)(
        Skissm__E2eeAddress *, Skissm__E2eeAddress *,
        uint8_t *, size_t
    );

    /**
     * @brief notify new face-to-face session messages from other devices received event
     * @param f2f_session
     */
    void (*on_f2f_session_ready)(
        Skissm__Session *
    );

    /**
     * @brief notify group msg received event
     * @param from_address
     * @param group_address
     * @param plaintext
     * @param plaintext_len
     */
    void (*on_group_msg_received)(
        Skissm__E2eeAddress *,
        Skissm__E2eeAddress *, uint8_t *, size_t
    );

    /**
     * @brief notify group created event
     * @param group_address
     * @param group_name
     */
    void (*on_group_created)(Skissm__E2eeAddress *, const char *);

    /**
     * @brief notify group members added
     * @param group_address
     * @param group_name
     * @param adding_group_members
     * @param adding_group_members_num
     */
    void (*on_group_members_added)(Skissm__E2eeAddress *, const char *, Skissm__GroupMember **, size_t);

    /**
     * @brief notify group members removed
     * @param group_address
     * @param group_name
     * @param removing_group_members
     * @param removing_group_members_num
     */
    void (*on_group_members_removed)(Skissm__E2eeAddress *, const char *, Skissm__GroupMember **, size_t);
} skissm_event_handler_t;

typedef struct skissm_plugin_t {
    skissm_common_handler_t common_handler;
    skissm_db_handler_t db_handler;
    e2ee_proto_handler_t proto_handler;
    skissm_event_handler_t event_handler;
} skissm_plugin_t;

typedef enum {
    INVITE_REQUEST,
    ACCEPT_REQUEST,
    PUBLISH_SPK_REQUEST,
    SUPPLY_OPKS_REQUEST,
    SEND_ONE2ONE_MSG_REQUEST,
    CREATE_GROUP_REQUEST,
    ADD_GROUP_MEMBERS_REQUEST,
    REMOVE_GROUP_MEMBERS_REQUEST,
    SEND_GROUP_MSG_REQUEST,
    PROTO_MSG
} resendable_request;

const e2ee_pack_t *get_e2ee_pack(const char *e2ee_pack_id);

void skissm_begin(skissm_plugin_t *ssm_plugin);

void skissm_end();

skissm_plugin_t *get_skissm_plugin();

void ssm_notify_log(LogCode, const char *, ...);
void ssm_notify_user_registered(Skissm__Account *account);
void ssm_notify_inbound_session_invited(Skissm__E2eeAddress *from);
void ssm_notify_inbound_session_ready(Skissm__Session *inbound_session);
void ssm_notify_outbound_session_ready(Skissm__Session *outbound_session);
void ssm_notify_one2one_msg(
    Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
);
void ssm_notify_other_device_msg(
    Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
);
void ssm_notify_f2f_session_ready(Skissm__Session *f2f_session);
void ssm_notify_group_msg(Skissm__E2eeAddress *from_address,
                          Skissm__E2eeAddress *group_address, uint8_t *plaintext,
                          size_t plaintext_len);
void ssm_notify_group_created(Skissm__E2eeAddress *group_address, const char *group_name);
void ssm_notify_group_members_added(Skissm__E2eeAddress *group_address,
                                    const char *group_name,
                                    Skissm__GroupMember **adding_group_members, size_t adding_group_members_num);
void ssm_notify_group_members_removed(Skissm__E2eeAddress *group_address,
                                      const char *group_name,
                                      Skissm__GroupMember **removing_group_members, size_t removing_group_members_num);

#ifdef __cplusplus
}
#endif

#endif /* SKISSM_H_ */
