/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: one_time_pre_key_pair.proto */

#ifndef PROTOBUF_C_one_5ftime_5fpre_5fkey_5fpair_2eproto__INCLUDED
#define PROTOBUF_C_one_5ftime_5fpre_5fkey_5fpair_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "key_pair.pb-c.h"

typedef struct _Org__E2eelab__Skissm__Proto__OneTimePreKeyPair Org__E2eelab__Skissm__Proto__OneTimePreKeyPair;


/* --- enums --- */


/* --- messages --- */

struct  _Org__E2eelab__Skissm__Proto__OneTimePreKeyPair
{
  ProtobufCMessage base;
  uint32_t opk_id;
  protobuf_c_boolean used;
  Org__E2eelab__Skissm__Proto__KeyPair *key_pair;
};
#define ORG__E2EELAB__SKISSM__PROTO__ONE_TIME_PRE_KEY_PAIR__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&org__e2eelab__skissm__proto__one_time_pre_key_pair__descriptor) \
    , 0, 0, NULL }


/* Org__E2eelab__Skissm__Proto__OneTimePreKeyPair methods */
void   org__e2eelab__skissm__proto__one_time_pre_key_pair__init
                     (Org__E2eelab__Skissm__Proto__OneTimePreKeyPair         *message);
size_t org__e2eelab__skissm__proto__one_time_pre_key_pair__get_packed_size
                     (const Org__E2eelab__Skissm__Proto__OneTimePreKeyPair   *message);
size_t org__e2eelab__skissm__proto__one_time_pre_key_pair__pack
                     (const Org__E2eelab__Skissm__Proto__OneTimePreKeyPair   *message,
                      uint8_t             *out);
size_t org__e2eelab__skissm__proto__one_time_pre_key_pair__pack_to_buffer
                     (const Org__E2eelab__Skissm__Proto__OneTimePreKeyPair   *message,
                      ProtobufCBuffer     *buffer);
Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *
       org__e2eelab__skissm__proto__one_time_pre_key_pair__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   org__e2eelab__skissm__proto__one_time_pre_key_pair__free_unpacked
                     (Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Org__E2eelab__Skissm__Proto__OneTimePreKeyPair_Closure)
                 (const Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor org__e2eelab__skissm__proto__one_time_pre_key_pair__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_one_5ftime_5fpre_5fkey_5fpair_2eproto__INCLUDED */
