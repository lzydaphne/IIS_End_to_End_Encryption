#ifndef E2EE_CLIENT_H_
#define E2EE_CLIENT_H_

#include "skissm/skissm.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Register a new account.
 *
 * @param account_id The unique account id.
 * @param e2ee_pack_id The e2ee package id to be used.
 * @param user_name The user name that is creating the new account.
 * @param device_id The device id that will be binded to the new account.
 * @param authenticator The authenticator (email and etc.) is used to receive an register auth code.
 * @param auth_code The auth code that is received by the authenticator.
 * @return size_t Return 0 for success
 */
size_t register_user(uint64_t account_id,
    const char *e2ee_pack_id,
    const char *user_name,
    const char *device_id,
    const char *authenticator,
    const char *auth_code);

/**
 * @brief Send invite request and create a new outbound session
 * that needs to be responded before it can be used
 * to send encryption message.
 * @param from From address
 * @param to To Address
 * @return  0 outbound session initialized, wait for being responded.
 *         -1 outbound session is already responded and ready to use.
 *         -2 outbound session is wait for responding.
 */
size_t invite(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to);

/**
 * @brief Send one2one msg.
 *
 * @param from
 * @param to
 * @param plaintext_data
 * @param plaintext_data_len
 * @return size_t Return 0 for success
 */
size_t send_one2one_msg(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to, const uint8_t *plaintext_data, size_t plaintext_data_len);

/**
 * @brief Create a group.
 *
 * @param sender_address
 * @param group_name
 * @param group_members
 * @param group_members_num
 * @return size_t Return 0 for success
 */
size_t create_group(Skissm__E2eeAddress *sender_address, const char *group_name, Skissm__GroupMember **group_members, size_t group_members_num);

/**
 * @brief Add group members.
 *
 * @param sender_address
 * @param group_address
 * @param adding_members
 * @param adding_members_num
 * @return size_t Return 0 for success
 */
size_t add_group_members(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **adding_members,
    size_t adding_members_num);

/**
 * @brief Remove group members.
 *
 * @param sender_address
 * @param group_address
 * @param removing_members
 * @param removing_members_num
 * @return size_t Return 0 for success
 */
size_t remove_group_members(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **removing_members,
    size_t removing_members_num);

/**
 * @brief Send group msg.
 *
 * @param sender_address
 * @param group_address
 * @param plaintext_data
 * @param plaintext_data_len
 * @return size_t Return 0 for success
 */
size_t send_group_msg(Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address, const uint8_t *plaintext_data, size_t plaintext_data_len);

/**
 * @brief Process incoming protocol messages.
 *
 * @param proto_msg_data
 * @param proto_msg_data_len
 * @return size_t Return 0 for success
 */
size_t process_proto_msg(uint8_t *proto_msg_data, size_t proto_msg_data_len);

#ifdef __cplusplus
}
#endif

#endif // E2EE_CLIENT_H_