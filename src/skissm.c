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
#include "skissm/skissm.h"

#include <stdarg.h>
#include <stdio.h>

#include "skissm/account.h"
#include "skissm/mem_util.h"

extern const struct cipher_suite_t E2EE_CIPHER_ECDH_X25519_AES256_GCM_SHA256;
extern const struct cipher_suite_t E2EE_CIPHER_KYBER_SPHINCSPLUS_SHA256_256S_AES256_GCM_SHA256;

extern const struct session_suite_t E2EE_SESSION_ECDH_X25519_AES256_GCM_SHA256;
extern const struct session_suite_t E2EE_SESSION_KYBER_SPHINCSPLUS_SHA256_256S_AES256_GCM_SHA256;

const struct e2ee_pack_t E2EE_PACK_ECDH_X25519_AES256_GCM_SHA256 = {
    E2EE_PACK_ID_ECC_DEFAULT,
    &E2EE_CIPHER_ECDH_X25519_AES256_GCM_SHA256,
    &E2EE_SESSION_ECDH_X25519_AES256_GCM_SHA256
};

const struct e2ee_pack_t E2EE_PACK_KYBER_SPHINCSPLUS_SHA256_256S_AES256_GCM_SHA256 = {
    E2EE_PACK_ID_PQC_DEFAULT,
    &E2EE_CIPHER_KYBER_SPHINCSPLUS_SHA256_256S_AES256_GCM_SHA256,
    &E2EE_SESSION_KYBER_SPHINCSPLUS_SHA256_256S_AES256_GCM_SHA256
};

const struct e2ee_pack_list_t E2EE_PACK_LIST = {
    &E2EE_PACK_ECDH_X25519_AES256_GCM_SHA256,
    &E2EE_PACK_KYBER_SPHINCSPLUS_SHA256_256S_AES256_GCM_SHA256
};

static skissm_plugin_t *skissm_plugin;

void skissm_begin(skissm_plugin_t *ssm_plugin) {
    skissm_plugin = ssm_plugin;
    account_begin();
}

void skissm_end() {
    skissm_plugin = NULL;
    account_end();
}

skissm_plugin_t *get_skissm_plugin() {
    return skissm_plugin;
}

void ssm_notify_log(LogCode log_code, const char *msg_fmt, ...) {
    if (skissm_plugin != NULL) {
        char msg[256] = {0};
        va_list arg;
        va_start(arg, msg_fmt);
        vsnprintf(msg, 256, msg_fmt, arg);
        va_end(arg);
        skissm_plugin->event_handler.on_log(log_code, msg);
    }
}

void ssm_notify_user_registered(Skissm__Account *account){
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_user_registered(account);
}

void ssm_notify_inbound_session_invited(Skissm__E2eeAddress *from) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_inbound_session_invited(from);
}

void ssm_notify_inbound_session_ready(Skissm__Session *inbound_session) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_inbound_session_ready(inbound_session);
}

void ssm_notify_outbound_session_ready(Skissm__Session *outbound_session) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_outbound_session_ready(outbound_session);
}

void ssm_notify_one2one_msg(
    Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_one2one_msg_received(from_address, to_address, plaintext, plaintext_len);
}

void ssm_notify_other_device_msg(
    Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_other_device_msg_received(from_address, to_address, plaintext, plaintext_len);
}

void ssm_notify_f2f_session_ready(Skissm__Session *f2f_session) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_f2f_session_ready(f2f_session);
}

void ssm_notify_group_msg(
    Skissm__E2eeAddress *from_address,
    Skissm__E2eeAddress *group_address,
    uint8_t *plaintext,
    size_t plaintext_len
) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_group_msg_received(from_address, group_address, plaintext, plaintext_len);
}

void ssm_notify_group_created(Skissm__E2eeAddress *group_address, const char *group_name) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_group_created(group_address, group_name);
}

void ssm_notify_group_members_added(
    Skissm__E2eeAddress *group_address,
    const char *group_name,
    Skissm__GroupMember **adding_group_members,
    size_t adding_group_members_num
) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_group_members_added(group_address, group_name, adding_group_members, adding_group_members_num);
}

void ssm_notify_group_members_removed(
    Skissm__E2eeAddress *group_address,
    const char *group_name,
    Skissm__GroupMember **removing_group_members,
    size_t removing_group_members_num
) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_group_members_removed(group_address, group_name, removing_group_members, removing_group_members_num);
}

const e2ee_pack_t *get_e2ee_pack(const char *e2ee_pack_id) {
  if (safe_strcmp(e2ee_pack_id, E2EE_PACK_ID_ECC_DEFAULT)) {
    return E2EE_PACK_LIST.e2ee_pack_0;
  } else if (safe_strcmp(e2ee_pack_id, E2EE_PACK_ID_PQC_DEFAULT)) {
    return E2EE_PACK_LIST.e2ee_pack_1;
  } else{
    return NULL;
  }
}
