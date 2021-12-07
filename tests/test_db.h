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
#ifndef TEST_DB_H_
#define TEST_DB_H_

#include <sqlite3.h>

#include "skissm/skissm.h"

void test_db_begin();
void test_db_end();
void load_id(ProtobufCBinaryData **account_id);
size_t load_ids(ProtobufCBinaryData ***account_ids);
uint32_t load_version(ProtobufCBinaryData *account_id);
protobuf_c_boolean load_saved(ProtobufCBinaryData *account_id);

void load_address(ProtobufCBinaryData *account_id,
                  Skissm__E2eeAddress **address);
void load_identity_key_pair(
    ProtobufCBinaryData *account_id,
    Skissm__KeyPair **identity_key_pair);
void load_signed_pre_key_pair(
    ProtobufCBinaryData *account_id,
    Skissm__SignedPreKeyPair **signed_pre_key_pair);
int load_n_one_time_pre_keys(ProtobufCBinaryData *account_id);
uint32_t load_one_time_pre_keys(
    ProtobufCBinaryData *account_id,
    Skissm__OneTimePreKeyPair ***one_time_pre_keys);
uint32_t load_next_signed_pre_key_id(ProtobufCBinaryData *account_id);
uint32_t load_next_one_time_pre_key_id(ProtobufCBinaryData *account_id);
void load_id_by_address(Skissm__E2eeAddress *address,
                        ProtobufCBinaryData **account_id);
sqlite_int64
insert_address(Skissm__E2eeAddress *address);
sqlite_int64 insert_key_pair(Skissm__KeyPair *key_pair);
sqlite_int64 insert_signed_pre_key(
    Skissm__SignedPreKeyPair *signed_pre_key);
sqlite_int64 insert_one_time_pre_key(
    Skissm__OneTimePreKeyPair *one_time_pre_key);
sqlite_int64 insert_account(ProtobufCBinaryData *account_id, int version,
                            protobuf_c_boolean saved, sqlite_int64 address_id,
                            sqlite_int64 identity_key_pair_id,
                            sqlite_int64 signed_pre_key_id,
                            sqlite_int64 next_signed_pre_key_id,
                            sqlite_int64 next_one_time_pre_key_id);
void insert_account_signed_pre_key_id(sqlite_int64 account_id,
                                      sqlite_int64 signed_pre_key_id);
void insert_account_one_time_pre_key_id(sqlite_int64 account_id,
                                        sqlite_int64 one_time_pre_key_id);
void update_identity_key(
    ProtobufCBinaryData *account_id,
    Skissm__KeyPair *identity_key_pair);
void update_signed_pre_key(
    ProtobufCBinaryData *account_id,
    Skissm__SignedPreKeyPair *signed_pre_key);
void load_old_signed_pre_key(ProtobufCBinaryData *account_id, uint32_t spk_id, Skissm__SignedPreKeyPair **signed_pre_key_pair);
void remove_expired_signed_pre_key(ProtobufCBinaryData *account_id);
void update_address(ProtobufCBinaryData *account_id,
                    Skissm__E2eeAddress *address);
void remove_one_time_pre_key(ProtobufCBinaryData *account_id, uint32_t one_time_pre_key_id);
void update_one_time_pre_key(ProtobufCBinaryData *account_id,
                             uint32_t one_time_pre_key_id);
void add_one_time_pre_key(
    ProtobufCBinaryData *account_id,
    Skissm__OneTimePreKeyPair *one_time_pre_key);
void load_inbound_session(ProtobufCBinaryData session_id,
                          Skissm__E2eeAddress *owner,
                          Skissm__E2eeSession **session);
void store_session(Skissm__E2eeSession *session);
void load_outbound_session(Skissm__E2eeAddress *owner,
                           Skissm__E2eeAddress *to,
                           Skissm__E2eeSession **session);
void unload_session(
    Skissm__E2eeAddress *owner,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to
);
void load_outbound_group_session(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__E2eeGroupSession **group_session);
void load_inbound_group_session(
    ProtobufCBinaryData group_session_id,
    Skissm__E2eeAddress *user_address,
    Skissm__E2eeGroupSession **group_session);
void store_group_session(
    Skissm__E2eeGroupSession *group_session);
void unload_group_session(
    Skissm__E2eeGroupSession *group_session);
void unload_inbound_group_session(
    Skissm__E2eeAddress *user_address,
    ProtobufCBinaryData *old_session_id
);

#endif /* TEST_DB_H_ */
