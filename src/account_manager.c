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
#include "skissm/account_manager.h"

#include <string.h>

#include "skissm/account.h"
#include "skissm/e2ee_client.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/mem_util.h"

Skissm__RegisterUserRequest *produce_register_request(Skissm__Account *account) {
    Skissm__RegisterUserRequest *request = (Skissm__RegisterUserRequest *)malloc(sizeof(Skissm__RegisterUserRequest));
    skissm__register_user_request__init(request);

    // copy identity public key
    request->identity_key_public = (Skissm__IdentityKeyPublic *)malloc(sizeof(Skissm__IdentityKeyPublic));
    skissm__identity_key_public__init(request->identity_key_public);
    copy_protobuf_from_protobuf(&(request->identity_key_public->asym_public_key), &(account->identity_key->asym_key_pair->public_key));
    copy_protobuf_from_protobuf(&(request->identity_key_public->sign_public_key), &(account->identity_key->sign_key_pair->public_key));

    // copy signed pre-key
    request->signed_pre_key_public = (Skissm__SignedPreKeyPublic *)malloc(sizeof(Skissm__SignedPreKeyPublic));
    skissm__signed_pre_key_public__init(request->signed_pre_key_public);
    request->signed_pre_key_public->spk_id = account->signed_pre_key->spk_id;
    copy_protobuf_from_protobuf(&(request->signed_pre_key_public->public_key), &(account->signed_pre_key->key_pair->public_key));
    copy_protobuf_from_protobuf(&(request->signed_pre_key_public->signature), &(account->signed_pre_key->signature));

    // copy one-time pre-key
    request->n_one_time_pre_keys = account->n_one_time_pre_keys;
    request->one_time_pre_keys = (Skissm__OneTimePreKeyPublic **)malloc(sizeof(Skissm__OneTimePreKeyPublic *) * request->n_one_time_pre_keys);
    size_t i;
    for (i = 0; i < request->n_one_time_pre_keys; i++) {
        request->one_time_pre_keys[i] = (Skissm__OneTimePreKeyPublic *)malloc(sizeof(Skissm__OneTimePreKeyPublic));
        skissm__one_time_pre_key_public__init(request->one_time_pre_keys[i]);
        request->one_time_pre_keys[i]->opk_id = account->one_time_pre_keys[i]->opk_id;
        copy_protobuf_from_protobuf(&(request->one_time_pre_keys[i]->public_key), &(account->one_time_pre_keys[i]->key_pair->public_key));
    }

    return request;
}

bool consume_register_response(Skissm__Account *account, Skissm__RegisterUserResponse *response) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        // insert the address the server gave to our account
        copy_address_from_address(&(account->address), response->address);
        account->saved = true;
        account->password = strdup(response->password);
        // save to db
        get_skissm_plugin()->db_handler.store_account(account);
        ssm_notify_user_registered(account);
        return true;
    } else {
        return false;
    }
}

Skissm__PublishSpkRequest *produce_publish_spk_request(Skissm__Account *account) {
    Skissm__PublishSpkRequest *request = (Skissm__PublishSpkRequest *)malloc(sizeof(Skissm__PublishSpkRequest));
    skissm__publish_spk_request__init(request);

    // copy the new signed pre-key to the message which will be sent to the server
    copy_address_from_address(&(request->user_address), account->address);
    request->signed_pre_key_public = (Skissm__SignedPreKeyPublic *)malloc(sizeof(Skissm__SignedPreKeyPublic));
    skissm__signed_pre_key_public__init(request->signed_pre_key_public);
    request->signed_pre_key_public->spk_id = account->signed_pre_key->spk_id;
    copy_protobuf_from_protobuf(&(request->signed_pre_key_public->public_key), &(account->signed_pre_key->key_pair->public_key));
    copy_protobuf_from_protobuf(&(request->signed_pre_key_public->signature), &(account->signed_pre_key->signature));

    return request;
}

bool consume_publish_spk_response(Skissm__Account *account, Skissm__PublishSpkResponse *response) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        // save to db
        if (account->saved == true) {
            Skissm__SignedPreKey *signed_pre_key = account->signed_pre_key;
            get_skissm_plugin()->db_handler.update_signed_pre_key(account->account_id, signed_pre_key);
        }
        return true;
    } else {
        return false;
    }
}

Skissm__SupplyOpksRequest *produce_supply_opks_request(Skissm__Account *account, uint32_t opks_num) {
    Skissm__SupplyOpksRequest *request = (Skissm__SupplyOpksRequest *)malloc(sizeof(Skissm__SupplyOpksRequest));
    skissm__supply_opks_request__init(request);

    // generate a given number of new one-time pre-keys
    Skissm__OneTimePreKey **inserted_one_time_pre_key_pair_list = generate_opks((size_t)opks_num, account);

    request->e2ee_pack_id = strdup(account->e2ee_pack_id);
    request->n_one_time_pre_key_public = (size_t)opks_num;
    request->one_time_pre_key_public = (Skissm__OneTimePreKeyPublic **)malloc(sizeof(Skissm__OneTimePreKeyPublic *) * opks_num);

    copy_address_from_address(&(request->user_address), account->address);

    // copy the new one-time pre-keys to the message which will be sent to the server
    uint32_t i;
    for (i = 0; i < opks_num; i++) {
        request->one_time_pre_key_public[i] = (Skissm__OneTimePreKeyPublic *)malloc(sizeof(Skissm__OneTimePreKeyPublic));
        skissm__one_time_pre_key_public__init(request->one_time_pre_key_public[i]);
        request->one_time_pre_key_public[i]->opk_id = inserted_one_time_pre_key_pair_list[i]->opk_id;
        copy_protobuf_from_protobuf(&(request->one_time_pre_key_public[i]->public_key), &(inserted_one_time_pre_key_pair_list[i]->key_pair->public_key));
    }

    return request;
}

bool consume_supply_opks_response(Skissm__Account *account, uint32_t opks_num, Skissm__SupplyOpksResponse *response) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        size_t old_opks_num = account->n_one_time_pre_keys - opks_num;
        // save to db
        size_t i;
        for (i = 0; i < opks_num; i++) {
            get_skissm_plugin()->db_handler.add_one_time_pre_key(account->account_id, account->one_time_pre_keys[old_opks_num + i]);
        }
        return true;
    } else {
        return false;
    }
}

bool consume_supply_opks_msg(Skissm__E2eeAddress *receiver_address, Skissm__SupplyOpksMsg *msg) {
    /** The server notifies us to generate some new one-time pre-keys 
        since our published one-time pre-keys are going to used up. */

    if (!compare_address(receiver_address, msg->user_address)){
        ssm_notify_error(BAD_SERVER_MESSAGE, "consume_supply_opks_msg()");
        return false;
    }

    uint32_t opks_num = msg->opks_num;
    Skissm__E2eeAddress *user_address = msg->user_address;
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(user_address, &account);

    if (account == NULL || !(account->saved)) {
        ssm_notify_error(BAD_ONE_TIME_PRE_KEY, "consume_supply_opks_msg()");
        return false;
    }

    Skissm__SupplyOpksResponse *response = supply_opks_internal(account, opks_num);

    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__supply_opks_response__free_unpacked(response, NULL);

    // done
    return true;
}