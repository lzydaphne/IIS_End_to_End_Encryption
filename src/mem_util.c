#include <string.h>

#include "mem_util.h"

bool is_equal(const uint8_t *buffer_a, const uint8_t *buffer_b, size_t length){
    uint8_t volatile result = 0;
    while (length--) {
        result |= (*(buffer_a++)) ^ (*(buffer_b++));
    }
    return result == 0;
}

bool compare_protobuf(ProtobufCBinaryData *src_1, ProtobufCBinaryData *src_2){
    if (src_1->len == src_2->len){
        if (memcmp(src_1->data, src_2->data, src_1->len) == 0){
            return true;
        }
    }
    return false;
}

bool compare_address(Org__E2eelab__Lib__Protobuf__E2eeAddress *address_1, Org__E2eelab__Lib__Protobuf__E2eeAddress *address_2){
    if ((address_1->user_id.len == address_2->user_id.len)
        && (address_1->domain.len == address_2->domain.len)
        && (address_1->device_id.len == address_2->device_id.len)
        && (address_1->group_id.len == address_2->group_id.len)
    ) {
        if ((memcmp(address_1->user_id.data, address_2->user_id.data, address_1->user_id.len) == 0)
            && (memcmp(address_1->domain.data, address_2->domain.data, address_1->domain.len) == 0)
            && (memcmp(address_1->device_id.data, address_2->device_id.data, address_1->device_id.len) == 0)
            && (memcmp(address_1->group_id.data, address_2->group_id.data, address_1->group_id.len) == 0)
        ) {
            return true;
        }
    }

    return false;
}

bool compare_member_addresses(
    Org__E2eelab__Lib__Protobuf__E2eeAddress **member_addresses_1, size_t member_num_1,
    Org__E2eelab__Lib__Protobuf__E2eeAddress **member_addresses_2, size_t member_num_2
) {
    if (member_num_1 != member_num_2){
        return false;
    }
    size_t i;
    for (i = 0; i < member_num_1; i++){
        if (compare_address(member_addresses_1[i], member_addresses_2[i]) == false){
            return false;
        }
    }
    return true;
}

void copy_protobuf_from_protobuf(ProtobufCBinaryData *dest, const ProtobufCBinaryData *src){
    dest->len = src->len;
    dest->data = (uint8_t *) malloc(sizeof(uint8_t) * src->len);
    memcpy(dest->data, src->data, src->len);
}

void copy_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src, size_t len){
    dest->len = len;
    dest->data = (uint8_t *) malloc(sizeof(uint8_t) * len);
    memcpy(dest->data, src, len);
}

void overwrite_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src){
    memcpy(dest->data, src, dest->len);
}

void copy_address_from_address(Org__E2eelab__Lib__Protobuf__E2eeAddress **dest, const Org__E2eelab__Lib__Protobuf__E2eeAddress *src){
    *dest = (Org__E2eelab__Lib__Protobuf__E2eeAddress *) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeAddress));
    org__e2eelab__lib__protobuf__e2ee_address__init(*dest);
    if (src->user_id.data){
        (*dest)->user_id.len = src->user_id.len;
        (*dest)->user_id.data = (uint8_t *) malloc(sizeof(uint8_t) * src->user_id.len);
        memcpy((*dest)->user_id.data, src->user_id.data, src->user_id.len);
    }
    if (src->domain.data){
        (*dest)->domain.len = src->domain.len;
        (*dest)->domain.data = (uint8_t *) malloc(sizeof(uint8_t) * src->domain.len);
        memcpy((*dest)->domain.data, src->domain.data, src->domain.len);
    }
    if (src->device_id.data){
        (*dest)->device_id.len = src->device_id.len;
        (*dest)->device_id.data = (uint8_t *) malloc(sizeof(uint8_t) * src->device_id.len);
        memcpy((*dest)->device_id.data, src->device_id.data, src->device_id.len);
    }
    if (src->group_id.data){
        (*dest)->group_id.len = src->group_id.len;
        (*dest)->group_id.data = (uint8_t *) malloc(sizeof(uint8_t) * src->group_id.len);
        memcpy((*dest)->group_id.data, src->group_id.data, src->group_id.len);
    }
}

void copy_member_addresses_from_member_addresses(
    Org__E2eelab__Lib__Protobuf__E2eeAddress ***dest,
    const Org__E2eelab__Lib__Protobuf__E2eeAddress **src,
    size_t member_num
) {
    *dest = (Org__E2eelab__Lib__Protobuf__E2eeAddress **) malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeAddress *) * member_num);
    size_t i;
    for (i = 0; i < member_num; i++){
        copy_address_from_address(&((*dest)[i]), src[i]);
    }
}

void free_protobuf(ProtobufCBinaryData *output){
    if (output->data) {
        unset(output->data, output->len);
        free(output->data);
    }
    output->len = 0;
    output->data = NULL;
}

void free_mem(void **buffer, size_t buffer_len){
    unset(*buffer, buffer_len);
    free(*buffer);
    *buffer = NULL;
}

void unset(void volatile *buffer, size_t buffer_len){
    char volatile *pos = (char volatile *)(buffer);
    char volatile *end = pos + buffer_len;
    while (pos != end) {
        *(pos++) = 0;
    }
}