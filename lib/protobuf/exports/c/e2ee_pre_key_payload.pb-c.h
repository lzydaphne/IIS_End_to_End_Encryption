/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: e2ee_pre_key_payload.proto */

#ifndef PROTOBUF_C_e2ee_5fpre_5fkey_5fpayload_2eproto__INCLUDED
#define PROTOBUF_C_e2ee_5fpre_5fkey_5fpayload_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "e2ee_msg_payload.pb-c.h"

typedef struct _Org__E2eelab__Skissm__Proto__E2eePreKeyPayload Org__E2eelab__Skissm__Proto__E2eePreKeyPayload;


/* --- enums --- */


/* --- messages --- */

struct  _Org__E2eelab__Skissm__Proto__E2eePreKeyPayload
{
  ProtobufCMessage base;
  ProtobufCBinaryData alice_identity_key;
  ProtobufCBinaryData alice_ephemeral_key;
  uint32_t bob_signed_pre_key_id;
  uint32_t bob_one_time_pre_key_id;
  Org__E2eelab__Skissm__Proto__E2eeMsgPayload *msg_payload;
};
#define ORG__E2EELAB__SKISSM__PROTO__E2EE_PRE_KEY_PAYLOAD__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&org__e2eelab__skissm__proto__e2ee_pre_key_payload__descriptor) \
    , {0,NULL}, {0,NULL}, 0, 0, NULL }


/* Org__E2eelab__Skissm__Proto__E2eePreKeyPayload methods */
void   org__e2eelab__skissm__proto__e2ee_pre_key_payload__init
                     (Org__E2eelab__Skissm__Proto__E2eePreKeyPayload         *message);
size_t org__e2eelab__skissm__proto__e2ee_pre_key_payload__get_packed_size
                     (const Org__E2eelab__Skissm__Proto__E2eePreKeyPayload   *message);
size_t org__e2eelab__skissm__proto__e2ee_pre_key_payload__pack
                     (const Org__E2eelab__Skissm__Proto__E2eePreKeyPayload   *message,
                      uint8_t             *out);
size_t org__e2eelab__skissm__proto__e2ee_pre_key_payload__pack_to_buffer
                     (const Org__E2eelab__Skissm__Proto__E2eePreKeyPayload   *message,
                      ProtobufCBuffer     *buffer);
Org__E2eelab__Skissm__Proto__E2eePreKeyPayload *
       org__e2eelab__skissm__proto__e2ee_pre_key_payload__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   org__e2eelab__skissm__proto__e2ee_pre_key_payload__free_unpacked
                     (Org__E2eelab__Skissm__Proto__E2eePreKeyPayload *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Org__E2eelab__Skissm__Proto__E2eePreKeyPayload_Closure)
                 (const Org__E2eelab__Skissm__Proto__E2eePreKeyPayload *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor org__e2eelab__skissm__proto__e2ee_pre_key_payload__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_e2ee_5fpre_5fkey_5fpayload_2eproto__INCLUDED */
