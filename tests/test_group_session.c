#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "group_session.h"
#include "group_session_manager.h"
#include "e2ee_protocol_handler.h"
#include "e2ee_protocol.h"
#include "account.h"
#include "mem_util.h"

#include "test_env.h"

extern register_user_response_handler register_user_response_handler_store;

extern store_group group;

static void on_error(ErrorCode error_code, char *error_msg) {
    printf("💀 ErrorCode: %d, ErrorMsg: %s\n", error_code, error_msg);
}

static void on_one2one_msg_received(
      Org__E2eelab__Lib__Protobuf__E2eeAddress *from_address,
      Org__E2eelab__Lib__Protobuf__E2eeAddress *to_address,
      uint8_t *plaintext, size_t plaintext_len) {
    printf("😊 on_one2one_msg_received: plaintext[len=%zu]: %s\n", plaintext_len, plaintext);
}

static void on_group_msg_received(
      Org__E2eelab__Lib__Protobuf__E2eeAddress *from_address,
      Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
      uint8_t *plaintext, size_t plaintext_len) {
    printf("😊 on_group_msg_received: plaintext[len=%zu]: %s\n", plaintext_len, plaintext);
}

static skissm_event_handler test_event_handler = {
  on_error,
  on_one2one_msg_received,
  on_group_msg_received
};

int main(){
    // test start
    setup();

    set_skissm_event_handler(&test_event_handler);

    // Prepare account
    Org__E2eelab__Lib__Protobuf__E2eeAccount *a_account = create_account();
    register_user_response_handler_store.account = a_account;
    send_register_user_request(a_account, &register_user_response_handler_store);

    Org__E2eelab__Lib__Protobuf__E2eeAccount *b_account = create_account();
    register_user_response_handler_store.account = b_account;
    send_register_user_request(b_account, &register_user_response_handler_store);

    Org__E2eelab__Lib__Protobuf__E2eeAccount *c_account = create_account();
    register_user_response_handler_store.account = c_account;
    send_register_user_request(c_account, &register_user_response_handler_store);

    // Alice invites Bob to create a group
    Org__E2eelab__Lib__Protobuf__E2eeAddress **member_addresses = (Org__E2eelab__Lib__Protobuf__E2eeAddress **) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeAddress *) * 2);
    copy_address_from_address(&(member_addresses[0]), a_account->address);
    copy_address_from_address(&(member_addresses[1]), b_account->address);

    ProtobufCBinaryData *group_name = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData));
    group_name->len = strlen("Group name");
    group_name->data = (uint8_t *) malloc(sizeof(uint8_t) * group_name->len);
    memcpy(group_name->data, "Group name", group_name->len);
    create_group(a_account->address, group_name, member_addresses, 2);

    // Alice sends a message to the group
    uint8_t plaintext[] = "This is the group session test.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    encrypt_group_session(a_account->address, group.group_address, plaintext, plaintext_len);

    // Alice invites Claire to join the group
    Org__E2eelab__Lib__Protobuf__E2eeAddress **new_member_addresses = (Org__E2eelab__Lib__Protobuf__E2eeAddress **) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeAddress *));
    copy_address_from_address(&(new_member_addresses[0]), c_account->address);
    size_t new_member_num = 1;
    size_t result = add_group_members(a_account->address, group.group_address, new_member_addresses, new_member_num);
    assert(result == 0);

    // Alice sends a message to the group
    uint8_t plaintext_2[] = "This message will be sent to Bob and Claire.";
    size_t plaintext_len_2 = sizeof(plaintext_2) - 1;
    encrypt_group_session(a_account->address, group.group_address, plaintext_2, plaintext_len_2);

    // Alice removes Claire out of the group
    remove_group_members(a_account->address, group.group_address, new_member_addresses, new_member_num);

    // release
    org__e2eelab__lib__protobuf__e2ee_account__free_unpacked(a_account, NULL);
    org__e2eelab__lib__protobuf__e2ee_account__free_unpacked(b_account, NULL);
    org__e2eelab__lib__protobuf__e2ee_account__free_unpacked(c_account, NULL);
    org__e2eelab__lib__protobuf__e2ee_address__free_unpacked(member_addresses[0], NULL);
    org__e2eelab__lib__protobuf__e2ee_address__free_unpacked(member_addresses[1], NULL);
    free(member_addresses);
    free_protobuf(group_name);
    org__e2eelab__lib__protobuf__e2ee_address__free_unpacked(new_member_addresses[0], NULL);
    free(new_member_addresses);

    // test stop
    tear_down();

    return 0;
}

