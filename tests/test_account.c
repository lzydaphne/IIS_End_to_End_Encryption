#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "skissm.h"
#include "e2ee_protocol.h"
#include "account.h"
#include "cipher.h"
#include "crypto.h"
#include "mem_util.h"

#include "test_env.h"

static void verify_one_time_pre_keys(Org__E2eelab__Lib__Protobuf__E2eeAccount *account, unsigned int n_one_time_pre_keys) {
    unsigned int i;

    assert(account->n_one_time_pre_keys == n_one_time_pre_keys);

    for (i = 0; i < account->n_one_time_pre_keys; i++){
        assert(account->one_time_pre_keys[i]->opk_id == i);
        assert(account->one_time_pre_keys[i]->key_pair->private_key.data != NULL);
        assert(account->one_time_pre_keys[i]->key_pair->private_key.len == CURVE25519_KEY_LENGTH);
        assert(account->one_time_pre_keys[i]->key_pair->public_key.data != NULL);
        assert(account->one_time_pre_keys[i]->key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    }
}

int main(){
    // test start
    setup();

    // Register test
    Org__E2eelab__Lib__Protobuf__E2eeAccount *account = create_account();

    assert(account->identity_key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->identity_key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key_pair->spk_id == 0);
    assert(account->signed_pre_key_pair->key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key_pair->key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key_pair->signature.len == CURVE_SIGNATURE_LENGTH);
    verify_one_time_pre_keys(account, 100);

    // Generate a new signed pre-key pair and a new signature
    generate_signed_pre_key(account);

    assert(account->signed_pre_key_pair->spk_id == 1);
    assert(account->signed_pre_key_pair->key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key_pair->key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key_pair->signature.len == CURVE_SIGNATURE_LENGTH);

    // Post some new one-time pre-keys test
    // Generate 80 one-time pre-key pairs
    Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair **output = generate_opks(80, account);

    verify_one_time_pre_keys(account, 180);

    // release
    org__e2eelab__lib__protobuf__e2ee_account__free_unpacked(account, NULL);

    // test stop.
    tear_down();
    return 0;
}