/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: e2ee_session.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "e2ee_session.pb-c.h"
void   org__e2eelab__lib__protobuf__e2ee_session__init
                     (Org__E2eelab__Lib__Protobuf__E2eeSession         *message)
{
  static const Org__E2eelab__Lib__Protobuf__E2eeSession init_value = ORG__E2EELAB__LIB__PROTOBUF__E2EE_SESSION__INIT;
  *message = init_value;
}
size_t org__e2eelab__lib__protobuf__e2ee_session__get_packed_size
                     (const Org__E2eelab__Lib__Protobuf__E2eeSession *message)
{
  assert(message->base.descriptor == &org__e2eelab__lib__protobuf__e2ee_session__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t org__e2eelab__lib__protobuf__e2ee_session__pack
                     (const Org__E2eelab__Lib__Protobuf__E2eeSession *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &org__e2eelab__lib__protobuf__e2ee_session__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t org__e2eelab__lib__protobuf__e2ee_session__pack_to_buffer
                     (const Org__E2eelab__Lib__Protobuf__E2eeSession *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &org__e2eelab__lib__protobuf__e2ee_session__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Org__E2eelab__Lib__Protobuf__E2eeSession *
       org__e2eelab__lib__protobuf__e2ee_session__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Org__E2eelab__Lib__Protobuf__E2eeSession *)
     protobuf_c_message_unpack (&org__e2eelab__lib__protobuf__e2ee_session__descriptor,
                                allocator, len, data);
}
void   org__e2eelab__lib__protobuf__e2ee_session__free_unpacked
                     (Org__E2eelab__Lib__Protobuf__E2eeSession *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &org__e2eelab__lib__protobuf__e2ee_session__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor org__e2eelab__lib__protobuf__e2ee_session__field_descriptors[12] =
{
  {
    "version",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__E2eeSession, version),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "session_id",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__E2eeSession, session_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "session_owner",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__E2eeSession, session_owner),
    &org__e2eelab__lib__protobuf__e2ee_address__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "from",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__E2eeSession, from),
    &org__e2eelab__lib__protobuf__e2ee_address__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "to",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__E2eeSession, to),
    &org__e2eelab__lib__protobuf__e2ee_address__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ratchet",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__E2eeSession, ratchet),
    &org__e2eelab__lib__protobuf__ratchet__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "alice_identity_key",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__E2eeSession, alice_identity_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "alice_ephemeral_key",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__E2eeSession, alice_ephemeral_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "bob_signed_pre_key",
    9,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__E2eeSession, bob_signed_pre_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "bob_one_time_pre_key",
    10,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__E2eeSession, bob_one_time_pre_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "responded",
    11,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__E2eeSession, responded),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "associated_data",
    12,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Org__E2eelab__Lib__Protobuf__E2eeSession, associated_data),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned org__e2eelab__lib__protobuf__e2ee_session__field_indices_by_name[] = {
  7,   /* field[7] = alice_ephemeral_key */
  6,   /* field[6] = alice_identity_key */
  11,   /* field[11] = associated_data */
  9,   /* field[9] = bob_one_time_pre_key */
  8,   /* field[8] = bob_signed_pre_key */
  3,   /* field[3] = from */
  5,   /* field[5] = ratchet */
  10,   /* field[10] = responded */
  1,   /* field[1] = session_id */
  2,   /* field[2] = session_owner */
  4,   /* field[4] = to */
  0,   /* field[0] = version */
};
static const ProtobufCIntRange org__e2eelab__lib__protobuf__e2ee_session__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 12 }
};
const ProtobufCMessageDescriptor org__e2eelab__lib__protobuf__e2ee_session__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "org.e2eelab.lib.protobuf.e2ee_session",
  "E2eeSession",
  "Org__E2eelab__Lib__Protobuf__E2eeSession",
  "org.e2eelab.lib.protobuf",
  sizeof(Org__E2eelab__Lib__Protobuf__E2eeSession),
  12,
  org__e2eelab__lib__protobuf__e2ee_session__field_descriptors,
  org__e2eelab__lib__protobuf__e2ee_session__field_indices_by_name,
  1,  org__e2eelab__lib__protobuf__e2ee_session__number_ranges,
  (ProtobufCMessageInit) org__e2eelab__lib__protobuf__e2ee_session__init,
  NULL,NULL,NULL    /* reserved[123] */
};
