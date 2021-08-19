#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "skissm.h"
#include "e2ee_protocol.h"
#include "e2ee_protocol_handler.h"
#include "account.h"
#include "account_manager.h"
#include "session.h"
#include "group_session.h"
#include "group_session_manager.h"
#include "mem_util.h"

#define REQUEST_HANDLERS_NUM    1
#define RESPONSE_CMD_FLAG   0x1000

void handle_supply_opks_request(
    uint32_t num,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *address,
    Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload **request_opks_response
);

void handle_create_group_request(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *receiver_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress **member_addresses,
    size_t member_num,
    Org__E2eelab__Lib__Protobuf__CreateGroupResponsePayload **create_group_response
);

void handle_add_group_members_request(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *receiver_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
    size_t adding_member_num,
    Org__E2eelab__Lib__Protobuf__E2eeAddress **adding_member_addresses,
    Org__E2eelab__Lib__Protobuf__AddGroupMembersResponsePayload **add_group_members_response
);

void handle_remove_group_members_request(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *receiver_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
    size_t member_num,
    Org__E2eelab__Lib__Protobuf__E2eeAddress **member_addresses,
    Org__E2eelab__Lib__Protobuf__RemoveGroupMembersResponsePayload **remove_group_members_response
);

typedef struct handler_entry_node {
    uint32_t key;
    void *handler;
    struct handler_entry_node *next;
} handler_entry_node;

static Org__E2eelab__Lib__Protobuf__E2eeAccount *_account = NULL;

static volatile uint32_t request_id = 0;

static volatile handler_entry *request_handlers_map[REQUEST_HANDLERS_NUM] = {NULL};
static volatile uint8_t next_request_handler_pos = 0;

static volatile handler_entry_node *response_handlers_map = NULL;

void protocol_begin(){
    request_id = 0;
    next_request_handler_pos = 0;
    handler_entry *entry = (handler_entry *) malloc(sizeof(handler_entry));
    entry->key = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__supply_opks;
    entry->handler = handle_supply_opks_request;
    add_request_handler(entry);
    response_handlers_map = NULL;
}

void protocol_end(){
    unsigned short i;
    for (i = 0; i < REQUEST_HANDLERS_NUM; i++){
        if (request_handlers_map[i]){
            free((void *)request_handlers_map[i]);
            request_handlers_map[i] = NULL;
        }
    }
    destroy_response_handlers_map();
}

uint32_t next_request_id() {
    return request_id++;
}

void add_request_handler(handler_entry *entry) {
    request_handlers_map[next_request_handler_pos] = entry;
    next_request_handler_pos++;
}

void remove_request_handler(handler_entry *entry) {
    unsigned short i;
    for(i=0; i<REQUEST_HANDLERS_NUM; i++) {
        handler_entry *entry1 = (handler_entry *)request_handlers_map[i];
        if (entry->key == entry1->key) {
            request_handlers_map[i] = NULL;
            next_request_handler_pos--;
            return;
        }
    }
}

void *get_request_handler(Org__E2eelab__Lib__Protobuf__E2eeCommands cmd) {
    unsigned short i;
    for(i=0; i<REQUEST_HANDLERS_NUM; i++) {
        handler_entry *entry = (handler_entry *)request_handlers_map[i];
        if (((uint32_t)cmd) == entry->key) {
            return entry->handler;
        }
    }
    return NULL;
}

void insert_response_handler(uint32_t id, void *response_handler) {
    handler_entry_node *prev = (handler_entry_node *)response_handlers_map;
    handler_entry_node *cur;
    if (prev != NULL){
        while (prev->next != NULL)
            prev = prev->next;
    }
    cur = (handler_entry_node *) malloc(sizeof(handler_entry_node));
    cur->key = id;
    cur->handler = response_handler;
    cur->next = NULL;
    if (prev != NULL){
        prev->next = cur;
    } else{
        response_handlers_map = cur;
    }
}

void delete_response_handler(uint32_t id) {
    handler_entry_node *cur = (handler_entry_node *)response_handlers_map;
    handler_entry_node *prev = NULL;
    while (cur != NULL){
        if (cur->key == id){
            if (prev != NULL){
                prev->next = cur->next;
                free(cur);
            } else{
                response_handlers_map = cur->next;
                free(cur);
            }
        }
        prev = cur;
        cur = cur->next;
    }
}

void *get_response_handler(uint32_t id) {
    handler_entry_node *cur = (handler_entry_node *)response_handlers_map;
    while (cur != NULL){
        if (cur->key == id){
            return cur->handler;
        }
        cur = cur->next;
    }
    return NULL;
}

void destroy_response_handlers_map() {
    handler_entry_node *cur = (handler_entry_node *)response_handlers_map;
    handler_entry_node *prev = NULL;
    while (cur != NULL){
        prev = cur;
        cur = cur->next;
        free(prev);
    }
    response_handlers_map = NULL;
}

void send_register_user_request(Org__E2eelab__Lib__Protobuf__E2eeAccount *account, register_user_response_handler *response_handler){
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_command_request = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__register_user;
    e2ee_command_request->id = next_request_id();
    Org__E2eelab__Lib__Protobuf__RegisterUserRequestPayload *payload = create_register_request_payload(account);

    e2ee_command_request->payload.len = org__e2eelab__lib__protobuf__register_user_request_payload__get_packed_size(payload);
    e2ee_command_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    org__e2eelab__lib__protobuf__register_user_request_payload__pack(payload, e2ee_command_request->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    ssm_handler.handle_send(packed_message, packed_message_len);

    // release
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    free_mem((void **)&packed_message, packed_message_len);
}

void send_publish_spk_request(Org__E2eelab__Lib__Protobuf__E2eeAccount *account, publish_spk_response_handler *response_handler){
    /* Generate a new signed pre-key pair and a new signature. */
    generate_signed_pre_key(account);

    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_command_request = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__publish_spk;
    e2ee_command_request->id = next_request_id();
    Org__E2eelab__Lib__Protobuf__PublishSpkRequestPayload *publish_spk_message = (Org__E2eelab__Lib__Protobuf__PublishSpkRequestPayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__PublishSpkRequestPayload));
    org__e2eelab__lib__protobuf__publish_spk_request_payload__init(publish_spk_message);

    copy_address_from_address(&(publish_spk_message->user_address), account->address);
    publish_spk_message->signed_pre_key_public = (Org__E2eelab__Lib__Protobuf__SignedPreKeyPublic *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__SignedPreKeyPublic));
    org__e2eelab__lib__protobuf__signed_pre_key_public__init(publish_spk_message->signed_pre_key_public);
    publish_spk_message->signed_pre_key_public->spk_id = account->signed_pre_key_pair->spk_id;
    copy_protobuf_from_protobuf(&(publish_spk_message->signed_pre_key_public->public_key), &(account->signed_pre_key_pair->key_pair->public_key));
    copy_protobuf_from_protobuf(&(publish_spk_message->signed_pre_key_public->signature), &(account->signed_pre_key_pair->signature));

    e2ee_command_request->payload.len = org__e2eelab__lib__protobuf__publish_spk_request_payload__get_packed_size(publish_spk_message);
    e2ee_command_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    org__e2eelab__lib__protobuf__publish_spk_request_payload__pack(publish_spk_message, e2ee_command_request->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    ssm_handler.handle_send(packed_message, packed_message_len);

    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    free_mem((void **)&packed_message, packed_message_len);
}

void handle_supply_opks_request(
    uint32_t num,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *address,
    Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload **request_opks_response
) {
    _account = get_local_account(address);
    Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair **inserted_one_time_pre_key_pair_list = generate_opks((size_t)num, _account);

    *request_opks_response = (Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload));
    org__e2eelab__lib__protobuf__supply_opks_response_payload__init(*request_opks_response);
    (*request_opks_response)->n_one_time_pre_key_public = (size_t)num;
    (*request_opks_response)->one_time_pre_key_public = (Org__E2eelab__Lib__Protobuf__OneTimePreKeyPublic **) malloc(sizeof(Org__E2eelab__Lib__Protobuf__OneTimePreKeyPublic *) * num);

    unsigned int i;
    for (i = 0; i < num; i++){
        (*request_opks_response)->one_time_pre_key_public[i] = (Org__E2eelab__Lib__Protobuf__OneTimePreKeyPublic *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__OneTimePreKeyPublic));
        org__e2eelab__lib__protobuf__one_time_pre_key_public__init((*request_opks_response)->one_time_pre_key_public[i]);
        (*request_opks_response)->one_time_pre_key_public[i]->opk_id = inserted_one_time_pre_key_pair_list[i]->opk_id;
        copy_protobuf_from_protobuf(&((*request_opks_response)->one_time_pre_key_public[i]->public_key), &(inserted_one_time_pre_key_pair_list[i]->key_pair->public_key));
    }

    copy_address_from_address(&((*request_opks_response)->user_address), _account->address);

    /* code */
    (*request_opks_response)->code = OK;
}

void handle_create_group_request(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *receiver_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress **member_addresses,
    size_t member_num,
    Org__E2eelab__Lib__Protobuf__CreateGroupResponsePayload **create_group_response
) {
    /* create a new outbound group session */
    create_outbound_group_session(receiver_address, group_address, member_addresses, member_num);

    /* prepare the response payload */
    *create_group_response = (Org__E2eelab__Lib__Protobuf__CreateGroupResponsePayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__CreateGroupResponsePayload));
    org__e2eelab__lib__protobuf__create_group_response_payload__init(*create_group_response);
    (*create_group_response)->code = OK;
}

void handle_add_group_members_request(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *receiver_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
    size_t adding_member_num,
    Org__E2eelab__Lib__Protobuf__E2eeAddress **adding_member_addresses,
    Org__E2eelab__Lib__Protobuf__AddGroupMembersResponsePayload **add_group_members_response
) {
    Org__E2eelab__Lib__Protobuf__E2eeGroupSession *group_session = NULL;
    ssm_handler.load_outbound_group_session(receiver_address, group_address, &group_session);

    // TODO: compare adding_member_addresses

    if (group_session != NULL){
        size_t new_member_num = group_session->n_member_addresses + adding_member_num;
        Org__E2eelab__Lib__Protobuf__E2eeAddress **new_member_addresses = (Org__E2eelab__Lib__Protobuf__E2eeAddress **) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeAddress *) * new_member_num);
        size_t i;
        for (i = 0; i < group_session->n_member_addresses; i++){
            copy_address_from_address(&(new_member_addresses[i]), (group_session->member_addresses)[i]);
        }
        for (i = 0; i < adding_member_num; i++){
            copy_address_from_address(&(new_member_addresses[group_session->n_member_addresses + i]), adding_member_addresses[i]);
        }
        /* delete the old group session */
        ssm_handler.unload_group_session(group_session);

        /* create a new outbound group session */
        create_outbound_group_session(receiver_address, group_address, new_member_addresses, new_member_num);
    } else{
        get_group_response_handler *handler = get_group_members(group_address);
        create_outbound_group_session(receiver_address, group_address, handler->member_addresses, handler->member_num);
    }

    /* prepare the response payload */
    *add_group_members_response = (Org__E2eelab__Lib__Protobuf__AddGroupMembersResponsePayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__AddGroupMembersResponsePayload));
    org__e2eelab__lib__protobuf__add_group_members_response_payload__init(*add_group_members_response);
    (*add_group_members_response)->code = OK;
}

void handle_remove_group_members_request(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *receiver_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
    size_t removing_member_num,
    Org__E2eelab__Lib__Protobuf__E2eeAddress **removing_member_addresses,
    Org__E2eelab__Lib__Protobuf__RemoveGroupMembersResponsePayload **remove_group_members_response
) {
    Org__E2eelab__Lib__Protobuf__E2eeGroupSession *group_session = NULL;
    ssm_handler.load_outbound_group_session(receiver_address, group_address, &group_session);

    size_t new_member_num = group_session->n_member_addresses - removing_member_num;
    Org__E2eelab__Lib__Protobuf__E2eeAddress **new_member_addresses = (Org__E2eelab__Lib__Protobuf__E2eeAddress **) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeAddress *) * new_member_num);
    size_t i = 0, j = 0;
    while (i < group_session->n_member_addresses){
        if (j < removing_member_num){
            if (compare_address(group_session->member_addresses[i], removing_member_addresses[j])){
                i++;
                j++;
            } else{
                copy_address_from_address(&(new_member_addresses[i - j]), group_session->member_addresses[i]);
                i++;
            }
        } else{
            copy_address_from_address(&(new_member_addresses[i - j]), group_session->member_addresses[i]);
            i++;
        }
    }
    /* delete the old group session */
    ssm_handler.unload_group_session(group_session);

    /* create a new outbound group session */
    create_outbound_group_session(receiver_address, group_address, new_member_addresses, new_member_num);

    /* prepare the response payload */
    *remove_group_members_response = (Org__E2eelab__Lib__Protobuf__RemoveGroupMembersResponsePayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__RemoveGroupMembersResponsePayload));
    org__e2eelab__lib__protobuf__remove_group_members_response_payload__init(*remove_group_members_response);
    (*remove_group_members_response)->code = OK;
}

void send_supply_opks_response(
    uint32_t request_id,
    Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload *request_opks_response,
    supply_opks_handler *handler
) {
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_command_request = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__supply_opks_response;
    e2ee_command_request->id = request_id;

    e2ee_command_request->payload.len = org__e2eelab__lib__protobuf__supply_opks_response_payload__get_packed_size(request_opks_response);
    e2ee_command_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    org__e2eelab__lib__protobuf__supply_opks_response_payload__pack(request_opks_response, e2ee_command_request->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    int result = ssm_handler.handle_send(packed_message, packed_message_len);
    if (result == 0){
        handler->account = get_local_account(request_opks_response->user_address);
        supply_opks(handler);
    }

    /* release */
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    free_mem((void **)&packed_message, packed_message_len);
}

void send_create_group_response(
    uint32_t request_id,
    Org__E2eelab__Lib__Protobuf__CreateGroupResponsePayload *create_group_response
) {
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_command_request = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__create_group_response;
    e2ee_command_request->id = request_id;

    e2ee_command_request->payload.len = org__e2eelab__lib__protobuf__create_group_response_payload__get_packed_size(create_group_response);
    e2ee_command_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    org__e2eelab__lib__protobuf__create_group_response_payload__pack(create_group_response, e2ee_command_request->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    ssm_handler.handle_send(packed_message, packed_message_len);

    /* release */
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    free_mem((void **)&packed_message, packed_message_len);
}

void send_add_group_members_response(
    uint32_t request_id,
    Org__E2eelab__Lib__Protobuf__AddGroupMembersResponsePayload *add_group_members_response
) {
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_command_request = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__add_group_members_response;
    e2ee_command_request->id = request_id;

    e2ee_command_request->payload.len = org__e2eelab__lib__protobuf__add_group_members_response_payload__get_packed_size(add_group_members_response);
    e2ee_command_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    org__e2eelab__lib__protobuf__add_group_members_response_payload__pack(add_group_members_response, e2ee_command_request->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    ssm_handler.handle_send(packed_message, packed_message_len);

    /* release */
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    free_mem((void **)&packed_message, packed_message_len);
}

void send_remove_group_members_response(
    uint32_t request_id,
    Org__E2eelab__Lib__Protobuf__RemoveGroupMembersResponsePayload *remove_group_members_response
) {
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_command_request = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__remove_group_members_response;
    e2ee_command_request->id = request_id;

    e2ee_command_request->payload.len = org__e2eelab__lib__protobuf__remove_group_members_response_payload__get_packed_size(remove_group_members_response);
    e2ee_command_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    org__e2eelab__lib__protobuf__remove_group_members_response_payload__pack(remove_group_members_response, e2ee_command_request->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    ssm_handler.handle_send(packed_message, packed_message_len);

    /* release */
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    free_mem((void **)&packed_message, packed_message_len);
}

/**
 * @Brif
 * {
 *   "e2eecmd":"get_pre_key_bundle",
 *   "e2ee_address": {
 *     "user_id":"xxx",
 *     "domain":"xxx",
 *     "device_id":"xxx",
 *     "group_id":"xxx"
 *   }
 * }
 */
void send_get_pre_key_bundle_request(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *e2ee_address,
    const uint8_t *plaintext, size_t plaintext_len,
    pre_key_bundle_response_handler *response_handler
) {
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_command_request = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__get_pre_key_bundle;
    e2ee_command_request->id = next_request_id();
    Org__E2eelab__Lib__Protobuf__GetPreKeyBundleRequestPayload *get_pre_key_bundle_message = (Org__E2eelab__Lib__Protobuf__GetPreKeyBundleRequestPayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__GetPreKeyBundleRequestPayload));
    org__e2eelab__lib__protobuf__get_pre_key_bundle_request_payload__init(get_pre_key_bundle_message);
    copy_address_from_address(&(get_pre_key_bundle_message->peer_address), e2ee_address);

    e2ee_command_request->payload.len = org__e2eelab__lib__protobuf__get_pre_key_bundle_request_payload__get_packed_size(get_pre_key_bundle_message);
    e2ee_command_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    org__e2eelab__lib__protobuf__get_pre_key_bundle_request_payload__pack(get_pre_key_bundle_message, e2ee_command_request->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    ssm_handler.handle_send(packed_message, packed_message_len);

    // release
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
}

void send_create_group_request(
    create_group_response_handler *response_handler
) {
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_command_request = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__create_group;
    e2ee_command_request->id = next_request_id();

    Org__E2eelab__Lib__Protobuf__CreateGroupRequestPayload *create_group_msg = (Org__E2eelab__Lib__Protobuf__CreateGroupRequestPayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__CreateGroupRequestPayload));
    org__e2eelab__lib__protobuf__create_group_request_payload__init(create_group_msg);

    copy_address_from_address(&(create_group_msg->sender_address), response_handler->sender_address);
    copy_protobuf_from_protobuf(&(create_group_msg->group_name), response_handler->group_name);
    create_group_msg->n_member_addresses = response_handler->member_num;
    copy_member_addresses_from_member_addresses(&(create_group_msg->member_addresses), (const Org__E2eelab__Lib__Protobuf__E2eeAddress **)response_handler->member_addresses, response_handler->member_num);

    e2ee_command_request->payload.len = org__e2eelab__lib__protobuf__create_group_request_payload__get_packed_size(create_group_msg);
    e2ee_command_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    org__e2eelab__lib__protobuf__create_group_request_payload__pack(create_group_msg, e2ee_command_request->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    ssm_handler.handle_send(packed_message, packed_message_len);

    // release
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
}

void send_get_group_request(
    get_group_response_handler *response_handler
) {
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_command_request = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__get_group;
    e2ee_command_request->id = next_request_id();

    Org__E2eelab__Lib__Protobuf__GetGroupRequestPayload *get_group_msg = (Org__E2eelab__Lib__Protobuf__GetGroupRequestPayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__GetGroupRequestPayload));
    org__e2eelab__lib__protobuf__get_group_request_payload__init(get_group_msg);
    copy_address_from_address(&(get_group_msg->group_address), response_handler->group_address);

    e2ee_command_request->payload.len = org__e2eelab__lib__protobuf__get_group_request_payload__get_packed_size(get_group_msg);
    e2ee_command_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    org__e2eelab__lib__protobuf__get_group_request_payload__pack(get_group_msg, e2ee_command_request->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    ssm_handler.handle_send(packed_message, packed_message_len);

    // release
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    org__e2eelab__lib__protobuf__get_group_request_payload__free_unpacked(get_group_msg, NULL);
}

void send_add_group_members_request(
    add_group_members_response_handler *response_handler
) {
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_command_request = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__add_group_members;
    e2ee_command_request->id = next_request_id();

    Org__E2eelab__Lib__Protobuf__AddGroupMembersRequestPayload *add_group_member_msg = (Org__E2eelab__Lib__Protobuf__AddGroupMembersRequestPayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__AddGroupMembersRequestPayload));
    org__e2eelab__lib__protobuf__add_group_members_request_payload__init(add_group_member_msg);

    copy_address_from_address(&(add_group_member_msg->sender_address), response_handler->outbound_group_session->session_owner);
    copy_address_from_address(&(add_group_member_msg->group_address), response_handler->outbound_group_session->group_address);
    add_group_member_msg->n_member_addresses = response_handler->adding_member_num;
    copy_member_addresses_from_member_addresses(&(add_group_member_msg->member_addresses), (const Org__E2eelab__Lib__Protobuf__E2eeAddress **)response_handler->adding_member_addresses, response_handler->adding_member_num);

    e2ee_command_request->payload.len = org__e2eelab__lib__protobuf__add_group_members_request_payload__get_packed_size(add_group_member_msg);
    e2ee_command_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    org__e2eelab__lib__protobuf__add_group_members_request_payload__pack(add_group_member_msg, e2ee_command_request->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    ssm_handler.handle_send(packed_message, packed_message_len);

    // release
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    org__e2eelab__lib__protobuf__add_group_members_request_payload__free_unpacked(add_group_member_msg, NULL);
}

void send_remove_group_members_request(
    remove_group_members_response_handler *response_handler
) {
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_command_request = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__remove_group_members;
    e2ee_command_request->id = next_request_id();

    Org__E2eelab__Lib__Protobuf__RemoveGroupMembersRequestPayload *remove_group_member_msg = (Org__E2eelab__Lib__Protobuf__RemoveGroupMembersRequestPayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__RemoveGroupMembersRequestPayload));
    org__e2eelab__lib__protobuf__remove_group_members_request_payload__init(remove_group_member_msg);

    copy_address_from_address(&(remove_group_member_msg->sender_address), response_handler->outbound_group_session->session_owner);
    copy_address_from_address(&(remove_group_member_msg->group_address), response_handler->outbound_group_session->group_address);
    remove_group_member_msg->n_member_addresses = response_handler->removing_member_num;
    copy_member_addresses_from_member_addresses(&(remove_group_member_msg->member_addresses), (const Org__E2eelab__Lib__Protobuf__E2eeAddress **)response_handler->removing_member_addresses, response_handler->removing_member_num);

    e2ee_command_request->payload.len = org__e2eelab__lib__protobuf__remove_group_members_request_payload__get_packed_size(remove_group_member_msg);
    e2ee_command_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    org__e2eelab__lib__protobuf__remove_group_members_request_payload__pack(remove_group_member_msg, e2ee_command_request->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    ssm_handler.handle_send(packed_message, packed_message_len);

    // release
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    org__e2eelab__lib__protobuf__remove_group_members_request_payload__free_unpacked(remove_group_member_msg, NULL);
}

void send_receive_msg_response(uint32_t request_id){
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_protocol_msg = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_protocol_msg);

    e2ee_protocol_msg->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__e2ee_msg_response;
    e2ee_protocol_msg->id = request_id;

    Org__E2eelab__Lib__Protobuf__E2eeMsgResponsePayload *response_payload = (Org__E2eelab__Lib__Protobuf__E2eeMsgResponsePayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeMsgResponsePayload));
    org__e2eelab__lib__protobuf__e2ee_msg_response_payload__init(response_payload);

    response_payload->code = OK;

    e2ee_protocol_msg->payload.len = org__e2eelab__lib__protobuf__e2ee_msg_response_payload__get_packed_size(response_payload);
    e2ee_protocol_msg->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_protocol_msg->payload.len);
    org__e2eelab__lib__protobuf__e2ee_msg_response_payload__pack(response_payload, e2ee_protocol_msg->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_protocol_msg);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_protocol_msg, packed_message);

    /* done */
    ssm_handler.handle_send(packed_message, packed_message_len);

    /* release */
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_protocol_msg, NULL);
    org__e2eelab__lib__protobuf__e2ee_msg_response_payload__free_unpacked(response_payload, NULL);
}

void send_receive_group_msg_response(uint32_t request_id){
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *e2ee_protocol_msg = (Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg));
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__init(e2ee_protocol_msg);

    e2ee_protocol_msg->cmd = ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__e2ee_group_msg_response;
    e2ee_protocol_msg->id = request_id;

    Org__E2eelab__Lib__Protobuf__E2eeGroupMsgResponsePayload *response_payload = (Org__E2eelab__Lib__Protobuf__E2eeGroupMsgResponsePayload *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeGroupMsgResponsePayload));
    org__e2eelab__lib__protobuf__e2ee_group_msg_response_payload__init(response_payload);

    response_payload->code = OK;

    e2ee_protocol_msg->payload.len = org__e2eelab__lib__protobuf__e2ee_group_msg_response_payload__get_packed_size(response_payload);
    e2ee_protocol_msg->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * e2ee_protocol_msg->payload.len);
    org__e2eelab__lib__protobuf__e2ee_group_msg_response_payload__pack(response_payload, e2ee_protocol_msg->payload.data);

    size_t packed_message_len = org__e2eelab__lib__protobuf__e2ee_protocol_msg__get_packed_size(e2ee_protocol_msg);
    uint8_t *packed_message = (uint8_t *) malloc(sizeof(uint8_t) * packed_message_len);
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__pack(e2ee_protocol_msg, packed_message);

    /* done */
    ssm_handler.handle_send(packed_message, packed_message_len);

    /* release */
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(e2ee_protocol_msg, NULL);
    org__e2eelab__lib__protobuf__e2ee_group_msg_response_payload__free_unpacked(response_payload, NULL);
}

static void process_request_msg(
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *request_msg,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *receiver_address
) {
    void *request_handler = NULL;
    request_handler = get_request_handler(request_msg->cmd);

    // handle commands
    switch (request_msg->cmd)
    {
    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__supply_opks:
        {
        Org__E2eelab__Lib__Protobuf__SupplyOpksRequestPayload *request_opks_payload = org__e2eelab__lib__protobuf__supply_opks_request_payload__unpack(NULL, request_msg->payload.len, request_msg->payload.data);
        uint32_t num = request_opks_payload->opks_num;
        Org__E2eelab__Lib__Protobuf__E2eeAddress *address = request_opks_payload->user_address;
        Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload *request_opks_response;
        handle_supply_opks_request(num, address, &request_opks_response);

        send_supply_opks_response(request_msg->id, request_opks_response, (supply_opks_handler *)request_handler);
        }
        break;

    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__create_group:
        {
        Org__E2eelab__Lib__Protobuf__CreateGroupRequestPayload *create_group_payload = org__e2eelab__lib__protobuf__create_group_request_payload__unpack(NULL, request_msg->payload.len, request_msg->payload.data);
        size_t member_num = create_group_payload->n_member_addresses;
        Org__E2eelab__Lib__Protobuf__E2eeAddress **member_addresses = create_group_payload->member_addresses;
        Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address = create_group_payload->group_address;
        Org__E2eelab__Lib__Protobuf__CreateGroupResponsePayload *create_group_response;
        handle_create_group_request(receiver_address, group_address, member_addresses, member_num, &create_group_response);

        send_create_group_response(request_msg->id, create_group_response);
        }
        break;

    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__add_group_members:
        {
        Org__E2eelab__Lib__Protobuf__AddGroupMembersRequestPayload *add_group_members_request_payload = org__e2eelab__lib__protobuf__add_group_members_request_payload__unpack(NULL, request_msg->payload.len, request_msg->payload.data);
        Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address = add_group_members_request_payload->group_address;
        size_t adding_member_num = add_group_members_request_payload->n_member_addresses;
        Org__E2eelab__Lib__Protobuf__E2eeAddress **adding_member_addresses = add_group_members_request_payload->member_addresses;
        Org__E2eelab__Lib__Protobuf__AddGroupMembersResponsePayload *add_group_members_response;
        handle_add_group_members_request(receiver_address, group_address, adding_member_num, adding_member_addresses, &add_group_members_response);

        send_add_group_members_response(request_msg->id, add_group_members_response);
        }
        break;

    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__remove_group_members:
        {
        Org__E2eelab__Lib__Protobuf__RemoveGroupMembersRequestPayload *remove_group_members_request_payload = org__e2eelab__lib__protobuf__remove_group_members_request_payload__unpack(NULL, request_msg->payload.len, request_msg->payload.data);
        Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address = remove_group_members_request_payload->group_address;
        size_t removing_member_num = remove_group_members_request_payload->n_member_addresses;
        Org__E2eelab__Lib__Protobuf__E2eeAddress **removing_member_addresses = remove_group_members_request_payload->member_addresses;
        Org__E2eelab__Lib__Protobuf__RemoveGroupMembersResponsePayload *remove_group_members_response;
        handle_remove_group_members_request(receiver_address, group_address, removing_member_num, removing_member_addresses, &remove_group_members_response);

        send_remove_group_members_response(request_msg->id, remove_group_members_response);
        }
        break;

    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__e2ee_msg:
        {
        Org__E2eelab__Lib__Protobuf__E2eeMessage *receive_msg_payload = org__e2eelab__lib__protobuf__e2ee_message__unpack(NULL, request_msg->payload.len, request_msg->payload.data);

        size_t result = decrypt_session(receive_msg_payload);

        send_receive_msg_response(request_msg->id); // TODO: result
        }
        break;

    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__e2ee_group_msg:
        {
        Org__E2eelab__Lib__Protobuf__E2eeMessage *receive_msg_payload = org__e2eelab__lib__protobuf__e2ee_message__unpack(NULL, request_msg->payload.len, request_msg->payload.data);

        decrypt_group_session(receiver_address, receive_msg_payload);

        send_receive_group_msg_response(request_msg->id);
        }
        break;

    default:
        break;
    }
}

static void process_response_msg(Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *response_msg) {
    void *response_handler = NULL;

    response_handler = get_response_handler(response_msg->id);
    if (response_handler == NULL){
        return;
    }
    delete_response_handler(response_msg->id);

    // handle commands
    switch (response_msg->cmd)
    {
    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__register_user_response:
        {
        Org__E2eelab__Lib__Protobuf__RegisterUserResponsePayload *payload = org__e2eelab__lib__protobuf__register_user_response_payload__unpack(NULL, response_msg->payload.len, response_msg->payload.data);
        if (payload == NULL){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        if (payload->code != OK){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        ((register_user_response_handler *)response_handler)->handle_response(response_handler, payload->address);
        }
        break;

    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__delete_user_response:
        /* code */
        break;

    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__get_pre_key_bundle_response:
        {
        Org__E2eelab__Lib__Protobuf__GetPreKeyBundleResponsePayload *bundle_payload = org__e2eelab__lib__protobuf__get_pre_key_bundle_response_payload__unpack(NULL, response_msg->payload.len, response_msg->payload.data);
        if (bundle_payload == NULL){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        if (bundle_payload->code != OK){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }

        Org__E2eelab__Lib__Protobuf__PreKeyBundle *their_pre_key_bundle = bundle_payload->pre_key_bundle;

        pre_key_bundle_response_handler *this_response_handler = (pre_key_bundle_response_handler *)response_handler;
        Org__E2eelab__Lib__Protobuf__E2eeAddress *from = this_response_handler->from;
        Org__E2eelab__Lib__Protobuf__E2eeAddress *to = this_response_handler->to;
        uint8_t *plaintext = this_response_handler->plaintext;
        size_t plaintext_len = this_response_handler->plaintext_len;
        this_response_handler->on_receive_pre_key_bundle(
            their_pre_key_bundle, from, to, plaintext, plaintext_len);
        }
        break;

    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__publish_spk_response:
        {
        Org__E2eelab__Lib__Protobuf__PublishSpkResponsePayload *spk_payload = org__e2eelab__lib__protobuf__publish_spk_response_payload__unpack(NULL, response_msg->payload.len, response_msg->payload.data);
        if (spk_payload == NULL){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        if (spk_payload->code != OK){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }

        ((publish_spk_response_handler *)response_handler)->handle_response(response_handler);
        }
        break;

    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__create_group_response:
        {
        Org__E2eelab__Lib__Protobuf__CreateGroupResponsePayload *create_group_response_payload = org__e2eelab__lib__protobuf__create_group_response_payload__unpack(NULL, response_msg->payload.len, response_msg->payload.data);
        if (create_group_response_payload == NULL){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        if (create_group_response_payload->code != OK){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        ((create_group_response_handler *)response_handler)->handle_response(response_handler, create_group_response_payload->group_address);
        }
        break;

    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__get_group_response:
        {
        Org__E2eelab__Lib__Protobuf__GetGroupResponsePayload *get_group_response_payload = org__e2eelab__lib__protobuf__get_group_response_payload__unpack(NULL, response_msg->payload.len, response_msg->payload.data);
        if (get_group_response_payload == NULL){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        if (get_group_response_payload->code != OK){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        ((get_group_response_handler *)response_handler)->handle_response(response_handler, &(get_group_response_payload->group_name), get_group_response_payload->n_member_addresses, get_group_response_payload->member_addresses);
        }
        break;

    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__add_group_members_response:
        {
        Org__E2eelab__Lib__Protobuf__AddGroupMembersResponsePayload *add_group_members_response_payload = org__e2eelab__lib__protobuf__add_group_members_response_payload__unpack(NULL, response_msg->payload.len, response_msg->payload.data);
        if (add_group_members_response_payload == NULL){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        if (add_group_members_response_payload->code != OK){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        ((add_group_members_response_handler *)response_handler)->handle_response(response_handler);
        }
        break;

    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__remove_group_members_response:
        {
        Org__E2eelab__Lib__Protobuf__RemoveGroupMembersResponsePayload *remove_group_members_response_payload = org__e2eelab__lib__protobuf__remove_group_members_response_payload__unpack(NULL, response_msg->payload.len, response_msg->payload.data);
        if (remove_group_members_response_payload == NULL){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        if (remove_group_members_response_payload->code != OK){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        ((remove_group_members_response_handler *)response_handler)->handle_response(response_handler);
        }
        break;
    
    case ORG__E2EELAB__LIB__PROTOBUF__E2EE_COMMANDS__e2ee_msg_response:
        {
        Org__E2eelab__Lib__Protobuf__E2eeMsgResponsePayload *msg_payload = org__e2eelab__lib__protobuf__e2ee_msg_response_payload__unpack(NULL, response_msg->payload.len, response_msg->payload.data);
        if (msg_payload == NULL){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        if (msg_payload->code != OK){
            ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg()");
            break;
        }
        }
        break;

    default:
        break;
    }
}


/**
 * Parse incoming message from server
 *
 * Incoming commands
 *   register_user_response
 *      Server received the user's public keys and send the address to the user.
 *      {
 *         "user_id":"xxx",
 *         "domain":"xxx",
 *         "device_id":"xxx",
 *         "group_id":"xxx"
 *      }
 *   get_peer_bundle_response
 *      {
 *         "e2eecmd":"get_peer_bundle_response",
 *         "data":{
 *            "identity_key":"$base64of($identity_key)",
 *            "signed_pre_key":{"id":$id,"public_key":"$base64of($public_key)"},
 *            "signature":"$base64of($signature)",
 *            "one_time_pre_key":{"id":$id,"public_key":"$base64of($one_time_pre_key)"}
 *         }
 *      }
 *   request_opks
 *      Server send this command to notify user to publish a set of one-time pre-keys.
 *      {
 *         "e2eecmd":"request_opks",
 *         "data":{"num":$num}
 *      }
 */
void process_protocol_msg(
    uint8_t *server_msg, size_t server_msg_len,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *receiver_address
) {
    Org__E2eelab__Lib__Protobuf__E2eeProtocolMsg *protocol_msg = org__e2eelab__lib__protobuf__e2ee_protocol_msg__unpack(NULL, server_msg_len, server_msg);
    if (protocol_msg == NULL){
       ssm_notify_error(BAD_SERVER_MESSAGE, "parse_incoming_message()");
       return;
    }

    Org__E2eelab__Lib__Protobuf__E2eeCommands e2ee_command = protocol_msg->cmd;

    if (e2ee_command & RESPONSE_CMD_FLAG)
        process_response_msg(protocol_msg);
    else
        process_request_msg(protocol_msg, receiver_address);

    // release
    org__e2eelab__lib__protobuf__e2ee_protocol_msg__free_unpacked(protocol_msg, NULL);
}