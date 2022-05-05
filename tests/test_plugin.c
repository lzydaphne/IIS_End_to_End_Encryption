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
#include "test_plugin.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <sqlite3.h>
#include <string.h>

#include "skissm/cipher.h"
#include "skissm/crypto.h"
#include "skissm/e2ee_client.h"
#include "skissm/mem_util.h"

#include "test_server.h"
#include "test_db.h"
#include "test_util.h"

// utility functions
char *create_domain_str() {
    char *domain_str = strdup(E2EELAB_DOMAIN);
    return domain_str;
}

void create_domain(ProtobufCBinaryData *domain) {
    domain->len = sizeof(E2EELAB_DOMAIN);
    domain->data = (uint8_t *)malloc(sizeof(uint8_t) * domain->len);
    memcpy(domain->data, E2EELAB_DOMAIN, domain->len);
}

// ===============================================================
static int64_t handle_get_ts() {
    time_t now = time(0);
    return now;
}

static void handle_gen_rand(uint8_t *rand_out, size_t rand_out_len) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < rand_out_len; i++) {
        rand_out[i] = random() % UCHAR_MAX;
    }
}

static void handle_gen_uuid(uint8_t uuid[UUID_LEN]) {
    handle_gen_rand(uuid, UUID_LEN);
}

// ===============================================================

void load_account(uint64_t account_id, Skissm__Account **account) {
    *account = (Skissm__Account *)malloc(sizeof(Skissm__Account));
    skissm__account__init((*account));

    (*account)->account_id = account_id;
    (*account)->version = load_version(account_id);
    (*account)->saved = load_saved(account_id);
    load_address(account_id, &((*account)->address));
    load_password(account_id, (*account)->password);

    load_signed_pre_key_pair(account_id, &((*account)->signed_pre_key));
    load_identity_key_pair(account_id, &((*account)->identity_key));
    (*account)->n_one_time_pre_keys = load_one_time_pre_keys(account_id, &((*account)->one_time_pre_keys));
    (*account)->next_one_time_pre_key_id = load_next_one_time_pre_key_id(account_id);
}

size_t load_accounts(Skissm__Account ***accounts) {
    // load all account_ids
    sqlite_int64 *account_ids;
    size_t num = load_ids(&account_ids);

    // load all account by account_ids
    if (num == 0) {
        *accounts = NULL;
    } else {
        *accounts = (Skissm__Account **)malloc(sizeof(Skissm__Account *) * num);
        for (int i = 0; i < num; i++) {
            load_account(account_ids[i], &(*accounts)[i]);
        }

        // release account_ids array
        free(account_ids);
    }

    // done
    return num;
}

void load_account_by_address(Skissm__E2eeAddress *address, Skissm__Account **account) {
    sqlite_int64 account_id;
    load_id_by_address(address, &account_id);
    load_account(account_id, account);
}

void store_account(Skissm__Account *account) {
    // insert address
    sqlite_int64 address_id = insert_address(account->address);

    // insert identity_key
    sqlite_int64 identity_key_pair_id = insert_identity_key(account->identity_key);

    // insert signed_pre_key
    sqlite_int64 signed_pre_key_id = insert_signed_pre_key(account->signed_pre_key);

    // insert one_time_pre_keys
    sqlite_int64 one_time_pre_key_ids[account->n_one_time_pre_keys];
    for (int i = 0; i < account->n_one_time_pre_keys; i++) {
        one_time_pre_key_ids[i] = insert_one_time_pre_key(account->one_time_pre_keys[i]);
    }

    // insert account
    sqlite_int64 account_id = account->account_id;
    insert_account(account_id, account->version, account->saved, address_id, account->password, account->e2ee_pack_id,
                   identity_key_pair_id, signed_pre_key_id, account->next_one_time_pre_key_id);

    // insert ACCOUNT_SIGNED_PRE_KEY_PAIR
    insert_account_signed_pre_key_id(account_id, signed_pre_key_id);

    // insert ACCOUNT_ONE_TIME_PRE_KEY_PAIR
    for (int i = 0; i < account->n_one_time_pre_keys; i++) {
        insert_account_one_time_pre_key_id(account_id, one_time_pre_key_ids[i]);
    }
}

// ===============================================================
// skissm_event_handler_t
// callback handlers
static void on_one2one_msg_received(Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *to_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_one2one_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_group_msg_received(Skissm__E2eeAddress *from_address, Skissm__E2eeAddress *group_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_group_msg_received: plaintext", plaintext, plaintext_len);
}

struct skissm_plugin_t ssm_plugin = {
    // common
    {
        handle_get_ts,
        handle_gen_rand,
        handle_gen_uuid
    },
    {
        // account
        store_account,
        load_account,
        load_account_by_address,
        load_accounts,
        update_identity_key,
        update_signed_pre_key,
        load_signed_pre_key,
        remove_expired_signed_pre_key,
        update_address,
        add_one_time_pre_key,
        remove_one_time_pre_key,
        update_one_time_pre_key,
        // session
        load_inbound_session,
        load_outbound_session,
        store_session,
        unload_session,
        load_outbound_group_session,
        load_inbound_group_session,
        store_group_session,
        unload_group_session,
        unload_inbound_group_session,
        // group pre-key
        store_group_pre_key,
        load_group_pre_keys,
        unload_group_pre_key
    },
    {
        test_register_user,
        test_get_pre_key_bundle,
        test_invite,
        test_accept,
        test_publish_spk,
        test_supply_opks,
        test_send_one2one_msg,
        test_create_group,
        test_add_group_members,
        test_remove_group_members,
        test_send_group_msg,
        test_consume_proto_msg
    },
    {
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        on_one2one_msg_received,
        on_group_msg_received,
        NULL,
        NULL,
        NULL
    }
};

// test case interface

void tear_up() {
    test_db_begin();
    skissm_begin(&ssm_plugin);
}

void tear_down() {
    test_db_end();
    skissm_end();
}
