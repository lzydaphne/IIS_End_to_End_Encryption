/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: chain_key.proto */

#ifndef PROTOBUF_C_chain_5fkey_2eproto__INCLUDED
#define PROTOBUF_C_chain_5fkey_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _Org__E2eelab__Lib__Protobuf__ChainKey Org__E2eelab__Lib__Protobuf__ChainKey;


/* --- enums --- */


/* --- messages --- */

struct  _Org__E2eelab__Lib__Protobuf__ChainKey
{
  ProtobufCMessage base;
  uint32_t index;
  ProtobufCBinaryData shared_key;
};
#define ORG__E2EELAB__LIB__PROTOBUF__CHAIN_KEY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&org__e2eelab__lib__protobuf__chain_key__descriptor) \
    , 0, {0,NULL} }


/* Org__E2eelab__Lib__Protobuf__ChainKey methods */
void   org__e2eelab__lib__protobuf__chain_key__init
                     (Org__E2eelab__Lib__Protobuf__ChainKey         *message);
size_t org__e2eelab__lib__protobuf__chain_key__get_packed_size
                     (const Org__E2eelab__Lib__Protobuf__ChainKey   *message);
size_t org__e2eelab__lib__protobuf__chain_key__pack
                     (const Org__E2eelab__Lib__Protobuf__ChainKey   *message,
                      uint8_t             *out);
size_t org__e2eelab__lib__protobuf__chain_key__pack_to_buffer
                     (const Org__E2eelab__Lib__Protobuf__ChainKey   *message,
                      ProtobufCBuffer     *buffer);
Org__E2eelab__Lib__Protobuf__ChainKey *
       org__e2eelab__lib__protobuf__chain_key__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   org__e2eelab__lib__protobuf__chain_key__free_unpacked
                     (Org__E2eelab__Lib__Protobuf__ChainKey *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Org__E2eelab__Lib__Protobuf__ChainKey_Closure)
                 (const Org__E2eelab__Lib__Protobuf__ChainKey *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor org__e2eelab__lib__protobuf__chain_key__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_chain_5fkey_2eproto__INCLUDED */
