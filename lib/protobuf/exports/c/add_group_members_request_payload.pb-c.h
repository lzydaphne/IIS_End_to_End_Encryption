/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: add_group_members_request_payload.proto */

#ifndef PROTOBUF_C_add_5fgroup_5fmembers_5frequest_5fpayload_2eproto__INCLUDED
#define PROTOBUF_C_add_5fgroup_5fmembers_5frequest_5fpayload_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "e2ee_address.pb-c.h"

typedef struct _Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload;


/* --- enums --- */


/* --- messages --- */

struct  _Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload
{
  ProtobufCMessage base;
  Org__E2eelab__Skissm__Proto__E2eeAddress *sender_address;
  Org__E2eelab__Skissm__Proto__E2eeAddress *group_address;
  size_t n_member_addresses;
  Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses;
};
#define ORG__E2EELAB__SKISSM__PROTO__ADD_GROUP_MEMBERS_REQUEST_PAYLOAD__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&org__e2eelab__skissm__proto__add_group_members_request_payload__descriptor) \
    , NULL, NULL, 0,NULL }


/* Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload methods */
void   org__e2eelab__skissm__proto__add_group_members_request_payload__init
                     (Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload         *message);
size_t org__e2eelab__skissm__proto__add_group_members_request_payload__get_packed_size
                     (const Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload   *message);
size_t org__e2eelab__skissm__proto__add_group_members_request_payload__pack
                     (const Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload   *message,
                      uint8_t             *out);
size_t org__e2eelab__skissm__proto__add_group_members_request_payload__pack_to_buffer
                     (const Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload   *message,
                      ProtobufCBuffer     *buffer);
Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload *
       org__e2eelab__skissm__proto__add_group_members_request_payload__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   org__e2eelab__skissm__proto__add_group_members_request_payload__free_unpacked
                     (Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload_Closure)
                 (const Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor org__e2eelab__skissm__proto__add_group_members_request_payload__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_add_5fgroup_5fmembers_5frequest_5fpayload_2eproto__INCLUDED */
