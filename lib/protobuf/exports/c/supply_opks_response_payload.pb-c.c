/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: supply_opks_response_payload.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "supply_opks_response_payload.pb-c.h"
void   org__e2eelab__lib__protobuf__supply_opks_response_payload__init
                     (Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload         *message)
{
  static const Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload init_value = ORG__E2EELAB__LIB__PROTOBUF__SUPPLY_OPKS_RESPONSE_PAYLOAD__INIT;
  *message = init_value;
}
size_t org__e2eelab__lib__protobuf__supply_opks_response_payload__get_packed_size
                     (const Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload *message)
{
  assert(message->base.descriptor == &org__e2eelab__lib__protobuf__supply_opks_response_payload__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t org__e2eelab__lib__protobuf__supply_opks_response_payload__pack
                     (const Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &org__e2eelab__lib__protobuf__supply_opks_response_payload__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t org__e2eelab__lib__protobuf__supply_opks_response_payload__pack_to_buffer
                     (const Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &org__e2eelab__lib__protobuf__supply_opks_response_payload__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload *
       org__e2eelab__lib__protobuf__supply_opks_response_payload__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload *)
     protobuf_c_message_unpack (&org__e2eelab__lib__protobuf__supply_opks_response_payload__descriptor,
                                allocator, len, data);
}
void   org__e2eelab__lib__protobuf__supply_opks_response_payload__free_unpacked
                     (Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &org__e2eelab__lib__protobuf__supply_opks_response_payload__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor org__e2eelab__lib__protobuf__supply_opks_response_payload__field_descriptors[4] =
{
  {
    "code",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload, code),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "msg",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload, msg),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "user_address",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload, user_address),
    &org__e2eelab__lib__protobuf__e2ee_address__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "one_time_pre_key_public",
    4,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload, n_one_time_pre_key_public),
    offsetof(Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload, one_time_pre_key_public),
    &org__e2eelab__lib__protobuf__one_time_pre_key_public__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned org__e2eelab__lib__protobuf__supply_opks_response_payload__field_indices_by_name[] = {
  0,   /* field[0] = code */
  1,   /* field[1] = msg */
  3,   /* field[3] = one_time_pre_key_public */
  2,   /* field[2] = user_address */
};
static const ProtobufCIntRange org__e2eelab__lib__protobuf__supply_opks_response_payload__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor org__e2eelab__lib__protobuf__supply_opks_response_payload__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "org.e2eelab.lib.protobuf.supply_opks_response_payload",
  "SupplyOpksResponsePayload",
  "Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload",
  "org.e2eelab.lib.protobuf",
  sizeof(Org__E2eelab__Lib__Protobuf__SupplyOpksResponsePayload),
  4,
  org__e2eelab__lib__protobuf__supply_opks_response_payload__field_descriptors,
  org__e2eelab__lib__protobuf__supply_opks_response_payload__field_indices_by_name,
  1,  org__e2eelab__lib__protobuf__supply_opks_response_payload__number_ranges,
  (ProtobufCMessageInit) org__e2eelab__lib__protobuf__supply_opks_response_payload__init,
  NULL,NULL,NULL    /* reserved[123] */
};
