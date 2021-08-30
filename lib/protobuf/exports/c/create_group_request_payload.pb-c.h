/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: create_group_request_payload.proto */

#ifndef PROTOBUF_C_create_5fgroup_5frequest_5fpayload_2eproto__INCLUDED
#define PROTOBUF_C_create_5fgroup_5frequest_5fpayload_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "e2ee_address.pb-c.h"

typedef struct _Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload;


/* --- enums --- */


/* --- messages --- */

struct  _Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload
{
  ProtobufCMessage base;
  Org__E2eelab__Skissm__Proto__E2eeAddress *sender_address;
  size_t n_member_addresses;
  Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses;
  ProtobufCBinaryData group_name;
  Org__E2eelab__Skissm__Proto__E2eeAddress *group_address;
};
#define ORG__E2EELAB__SKISSM__PROTO__CREATE_GROUP_REQUEST_PAYLOAD__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&org__e2eelab__skissm__proto__create_group_request_payload__descriptor) \
    , NULL, 0,NULL, {0,NULL}, NULL }


/* Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload methods */
void   org__e2eelab__skissm__proto__create_group_request_payload__init
                     (Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload         *message);
size_t org__e2eelab__skissm__proto__create_group_request_payload__get_packed_size
                     (const Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload   *message);
size_t org__e2eelab__skissm__proto__create_group_request_payload__pack
                     (const Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload   *message,
                      uint8_t             *out);
size_t org__e2eelab__skissm__proto__create_group_request_payload__pack_to_buffer
                     (const Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload   *message,
                      ProtobufCBuffer     *buffer);
Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload *
       org__e2eelab__skissm__proto__create_group_request_payload__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   org__e2eelab__skissm__proto__create_group_request_payload__free_unpacked
                     (Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload_Closure)
                 (const Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor org__e2eelab__skissm__proto__create_group_request_payload__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_create_5fgroup_5frequest_5fpayload_2eproto__INCLUDED */