/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: delete_user_request_payload.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "delete_user_request_payload.pb-c.h"
void   org__e2eelab__skissm__proto__delete_user_request_payload__init
                     (Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload         *message)
{
  static const Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload init_value = ORG__E2EELAB__SKISSM__PROTO__DELETE_USER_REQUEST_PAYLOAD__INIT;
  *message = init_value;
}
size_t org__e2eelab__skissm__proto__delete_user_request_payload__get_packed_size
                     (const Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload *message)
{
  assert(message->base.descriptor == &org__e2eelab__skissm__proto__delete_user_request_payload__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t org__e2eelab__skissm__proto__delete_user_request_payload__pack
                     (const Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &org__e2eelab__skissm__proto__delete_user_request_payload__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t org__e2eelab__skissm__proto__delete_user_request_payload__pack_to_buffer
                     (const Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &org__e2eelab__skissm__proto__delete_user_request_payload__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload *
       org__e2eelab__skissm__proto__delete_user_request_payload__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload *)
     protobuf_c_message_unpack (&org__e2eelab__skissm__proto__delete_user_request_payload__descriptor,
                                allocator, len, data);
}
void   org__e2eelab__skissm__proto__delete_user_request_payload__free_unpacked
                     (Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &org__e2eelab__skissm__proto__delete_user_request_payload__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor org__e2eelab__skissm__proto__delete_user_request_payload__field_descriptors[1] =
{
  {
    "address",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload, address),
    &org__e2eelab__skissm__proto__e2ee_address__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned org__e2eelab__skissm__proto__delete_user_request_payload__field_indices_by_name[] = {
  0,   /* field[0] = address */
};
static const ProtobufCIntRange org__e2eelab__skissm__proto__delete_user_request_payload__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor org__e2eelab__skissm__proto__delete_user_request_payload__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "org.e2eelab.skissm.proto.delete_user_request_payload",
  "DeleteUserRequestPayload",
  "Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload",
  "org.e2eelab.skissm.proto",
  sizeof(Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload),
  1,
  org__e2eelab__skissm__proto__delete_user_request_payload__field_descriptors,
  org__e2eelab__skissm__proto__delete_user_request_payload__field_indices_by_name,
  1,  org__e2eelab__skissm__proto__delete_user_request_payload__number_ranges,
  (ProtobufCMessageInit) org__e2eelab__skissm__proto__delete_user_request_payload__init,
  NULL,NULL,NULL    /* reserved[123] */
};