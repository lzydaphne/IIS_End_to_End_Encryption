/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: e2ee_protocol_msg.proto */

#ifndef PROTOBUF_C_e2ee_5fprotocol_5fmsg_2eproto__INCLUDED
#define PROTOBUF_C_e2ee_5fprotocol_5fmsg_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "e2ee_commands.pb-c.h"

typedef struct _Org__E2eelab__Skissm__Proto__E2eeProtocolMsg Org__E2eelab__Skissm__Proto__E2eeProtocolMsg;


/* --- enums --- */


/* --- messages --- */

struct  _Org__E2eelab__Skissm__Proto__E2eeProtocolMsg
{
  ProtobufCMessage base;
  uint32_t id;
  Org__E2eelab__Skissm__Proto__E2eeCommands cmd;
  ProtobufCBinaryData payload;
};
#define ORG__E2EELAB__SKISSM__PROTO__E2EE_PROTOCOL_MSG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&org__e2eelab__skissm__proto__e2ee_protocol_msg__descriptor) \
    , 0, ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__register_user, {0,NULL} }


/* Org__E2eelab__Skissm__Proto__E2eeProtocolMsg methods */
void   org__e2eelab__skissm__proto__e2ee_protocol_msg__init
                     (Org__E2eelab__Skissm__Proto__E2eeProtocolMsg         *message);
size_t org__e2eelab__skissm__proto__e2ee_protocol_msg__get_packed_size
                     (const Org__E2eelab__Skissm__Proto__E2eeProtocolMsg   *message);
size_t org__e2eelab__skissm__proto__e2ee_protocol_msg__pack
                     (const Org__E2eelab__Skissm__Proto__E2eeProtocolMsg   *message,
                      uint8_t             *out);
size_t org__e2eelab__skissm__proto__e2ee_protocol_msg__pack_to_buffer
                     (const Org__E2eelab__Skissm__Proto__E2eeProtocolMsg   *message,
                      ProtobufCBuffer     *buffer);
Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *
       org__e2eelab__skissm__proto__e2ee_protocol_msg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   org__e2eelab__skissm__proto__e2ee_protocol_msg__free_unpacked
                     (Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Org__E2eelab__Skissm__Proto__E2eeProtocolMsg_Closure)
                 (const Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor org__e2eelab__skissm__proto__e2ee_protocol_msg__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_e2ee_5fprotocol_5fmsg_2eproto__INCLUDED */