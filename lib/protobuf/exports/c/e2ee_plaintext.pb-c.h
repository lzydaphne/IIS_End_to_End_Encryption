/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: e2ee_plaintext.proto */

#ifndef PROTOBUF_C_e2ee_5fplaintext_2eproto__INCLUDED
#define PROTOBUF_C_e2ee_5fplaintext_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "e2ee_plaintext_type.pb-c.h"

typedef struct _Org__E2eelab__Skissm__Proto__E2eePlaintext Org__E2eelab__Skissm__Proto__E2eePlaintext;


/* --- enums --- */


/* --- messages --- */

struct  _Org__E2eelab__Skissm__Proto__E2eePlaintext
{
  ProtobufCMessage base;
  uint32_t version;
  Org__E2eelab__Skissm__Proto__E2eePlaintextType plaintext_type;
  ProtobufCBinaryData payload;
};
#define ORG__E2EELAB__SKISSM__PROTO__E2EE_PLAINTEXT__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&org__e2eelab__skissm__proto__e2ee_plaintext__descriptor) \
    , 0, ORG__E2EELAB__SKISSM__PROTO__E2EE_PLAINTEXT_TYPE__COMMON_MSG, {0,NULL} }


/* Org__E2eelab__Skissm__Proto__E2eePlaintext methods */
void   org__e2eelab__skissm__proto__e2ee_plaintext__init
                     (Org__E2eelab__Skissm__Proto__E2eePlaintext         *message);
size_t org__e2eelab__skissm__proto__e2ee_plaintext__get_packed_size
                     (const Org__E2eelab__Skissm__Proto__E2eePlaintext   *message);
size_t org__e2eelab__skissm__proto__e2ee_plaintext__pack
                     (const Org__E2eelab__Skissm__Proto__E2eePlaintext   *message,
                      uint8_t             *out);
size_t org__e2eelab__skissm__proto__e2ee_plaintext__pack_to_buffer
                     (const Org__E2eelab__Skissm__Proto__E2eePlaintext   *message,
                      ProtobufCBuffer     *buffer);
Org__E2eelab__Skissm__Proto__E2eePlaintext *
       org__e2eelab__skissm__proto__e2ee_plaintext__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   org__e2eelab__skissm__proto__e2ee_plaintext__free_unpacked
                     (Org__E2eelab__Skissm__Proto__E2eePlaintext *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Org__E2eelab__Skissm__Proto__E2eePlaintext_Closure)
                 (const Org__E2eelab__Skissm__Proto__E2eePlaintext *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor org__e2eelab__skissm__proto__e2ee_plaintext__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_e2ee_5fplaintext_2eproto__INCLUDED */