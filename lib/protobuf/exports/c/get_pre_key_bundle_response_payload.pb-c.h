/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: get_pre_key_bundle_response_payload.proto */

#ifndef PROTOBUF_C_get_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto__INCLUDED
#define PROTOBUF_C_get_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "e2ee_pre_key_bundle.pb-c.h"

typedef struct _Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload;


/* --- enums --- */


/* --- messages --- */

struct  _Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload
{
  ProtobufCMessage base;
  uint32_t code;
  char *msg;
  ProtobufCBinaryData user_name;
  Org__E2eelab__Skissm__Proto__E2eePreKeyBundle *pre_key_bundle;
};
#define ORG__E2EELAB__SKISSM__PROTO__GET_PRE_KEY_BUNDLE_RESPONSE_PAYLOAD__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&org__e2eelab__skissm__proto__get_pre_key_bundle_response_payload__descriptor) \
    , 0, (char *)protobuf_c_empty_string, {0,NULL}, NULL }


/* Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload methods */
void   org__e2eelab__skissm__proto__get_pre_key_bundle_response_payload__init
                     (Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload         *message);
size_t org__e2eelab__skissm__proto__get_pre_key_bundle_response_payload__get_packed_size
                     (const Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload   *message);
size_t org__e2eelab__skissm__proto__get_pre_key_bundle_response_payload__pack
                     (const Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload   *message,
                      uint8_t             *out);
size_t org__e2eelab__skissm__proto__get_pre_key_bundle_response_payload__pack_to_buffer
                     (const Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload   *message,
                      ProtobufCBuffer     *buffer);
Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload *
       org__e2eelab__skissm__proto__get_pre_key_bundle_response_payload__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   org__e2eelab__skissm__proto__get_pre_key_bundle_response_payload__free_unpacked
                     (Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload_Closure)
                 (const Org__E2eelab__Skissm__Proto__GetPreKeyBundleResponsePayload *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor org__e2eelab__skissm__proto__get_pre_key_bundle_response_payload__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_get_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto__INCLUDED */