// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/remove_group_members_request_payload.proto

#include "skissm/remove_group_members_request_payload.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG
namespace org {
namespace e2eelab {
namespace skissm {
namespace proto {
constexpr remove_group_members_request_payload::remove_group_members_request_payload(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : member_addresses_()
  , sender_address_(nullptr)
  , group_address_(nullptr){}
struct remove_group_members_request_payloadDefaultTypeInternal {
  constexpr remove_group_members_request_payloadDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~remove_group_members_request_payloadDefaultTypeInternal() {}
  union {
    remove_group_members_request_payload _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT remove_group_members_request_payloadDefaultTypeInternal _remove_group_members_request_payload_default_instance_;
}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org
static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::remove_group_members_request_payload, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::remove_group_members_request_payload, sender_address_),
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::remove_group_members_request_payload, group_address_),
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::remove_group_members_request_payload, member_addresses_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::org::e2eelab::skissm::proto::remove_group_members_request_payload)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::org::e2eelab::skissm::proto::_remove_group_members_request_payload_default_instance_),
};

const char descriptor_table_protodef_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n1skissm/remove_group_members_request_pa"
  "yload.proto\022\030org.e2eelab.skissm.proto\032\031s"
  "kissm/e2ee_address.proto\"\347\001\n$remove_grou"
  "p_members_request_payload\022>\n\016sender_addr"
  "ess\030\001 \001(\0132&.org.e2eelab.skissm.proto.e2e"
  "e_address\022=\n\rgroup_address\030\002 \001(\0132&.org.e"
  "2eelab.skissm.proto.e2ee_address\022@\n\020memb"
  "er_addresses\030\003 \003(\0132&.org.e2eelab.skissm."
  "proto.e2ee_addressB\"B RemoveGroupMembers"
  "RequestPayloadb\006proto3"
  ;
static const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable*const descriptor_table_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto_deps[1] = {
  &::descriptor_table_skissm_2fe2ee_5faddress_2eproto,
};
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto = {
  false, false, 382, descriptor_table_protodef_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto, "skissm/remove_group_members_request_payload.proto", 
  &descriptor_table_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto_once, descriptor_table_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto_deps, 1, 1,
  schemas, file_default_instances, TableStruct_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto::offsets,
  file_level_metadata_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto, file_level_enum_descriptors_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto, file_level_service_descriptors_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable* descriptor_table_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto_getter() {
  return &descriptor_table_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY static ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptorsRunner dynamic_init_dummy_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto(&descriptor_table_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto);
namespace org {
namespace e2eelab {
namespace skissm {
namespace proto {

// ===================================================================

class remove_group_members_request_payload::_Internal {
 public:
  static const ::org::e2eelab::skissm::proto::e2ee_address& sender_address(const remove_group_members_request_payload* msg);
  static const ::org::e2eelab::skissm::proto::e2ee_address& group_address(const remove_group_members_request_payload* msg);
};

const ::org::e2eelab::skissm::proto::e2ee_address&
remove_group_members_request_payload::_Internal::sender_address(const remove_group_members_request_payload* msg) {
  return *msg->sender_address_;
}
const ::org::e2eelab::skissm::proto::e2ee_address&
remove_group_members_request_payload::_Internal::group_address(const remove_group_members_request_payload* msg) {
  return *msg->group_address_;
}
void remove_group_members_request_payload::clear_sender_address() {
  if (GetArenaForAllocation() == nullptr && sender_address_ != nullptr) {
    delete sender_address_;
  }
  sender_address_ = nullptr;
}
void remove_group_members_request_payload::clear_group_address() {
  if (GetArenaForAllocation() == nullptr && group_address_ != nullptr) {
    delete group_address_;
  }
  group_address_ = nullptr;
}
void remove_group_members_request_payload::clear_member_addresses() {
  member_addresses_.Clear();
}
remove_group_members_request_payload::remove_group_members_request_payload(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned),
  member_addresses_(arena) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:org.e2eelab.skissm.proto.remove_group_members_request_payload)
}
remove_group_members_request_payload::remove_group_members_request_payload(const remove_group_members_request_payload& from)
  : ::PROTOBUF_NAMESPACE_ID::Message(),
      member_addresses_(from.member_addresses_) {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  if (from._internal_has_sender_address()) {
    sender_address_ = new ::org::e2eelab::skissm::proto::e2ee_address(*from.sender_address_);
  } else {
    sender_address_ = nullptr;
  }
  if (from._internal_has_group_address()) {
    group_address_ = new ::org::e2eelab::skissm::proto::e2ee_address(*from.group_address_);
  } else {
    group_address_ = nullptr;
  }
  // @@protoc_insertion_point(copy_constructor:org.e2eelab.skissm.proto.remove_group_members_request_payload)
}

inline void remove_group_members_request_payload::SharedCtor() {
::memset(reinterpret_cast<char*>(this) + static_cast<size_t>(
    reinterpret_cast<char*>(&sender_address_) - reinterpret_cast<char*>(this)),
    0, static_cast<size_t>(reinterpret_cast<char*>(&group_address_) -
    reinterpret_cast<char*>(&sender_address_)) + sizeof(group_address_));
}

remove_group_members_request_payload::~remove_group_members_request_payload() {
  // @@protoc_insertion_point(destructor:org.e2eelab.skissm.proto.remove_group_members_request_payload)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

inline void remove_group_members_request_payload::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  if (this != internal_default_instance()) delete sender_address_;
  if (this != internal_default_instance()) delete group_address_;
}

void remove_group_members_request_payload::ArenaDtor(void* object) {
  remove_group_members_request_payload* _this = reinterpret_cast< remove_group_members_request_payload* >(object);
  (void)_this;
}
void remove_group_members_request_payload::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void remove_group_members_request_payload::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void remove_group_members_request_payload::Clear() {
// @@protoc_insertion_point(message_clear_start:org.e2eelab.skissm.proto.remove_group_members_request_payload)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  member_addresses_.Clear();
  if (GetArenaForAllocation() == nullptr && sender_address_ != nullptr) {
    delete sender_address_;
  }
  sender_address_ = nullptr;
  if (GetArenaForAllocation() == nullptr && group_address_ != nullptr) {
    delete group_address_;
  }
  group_address_ = nullptr;
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* remove_group_members_request_payload::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // .org.e2eelab.skissm.proto.e2ee_address sender_address = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          ptr = ctx->ParseMessage(_internal_mutable_sender_address(), ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // .org.e2eelab.skissm.proto.e2ee_address group_address = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 18)) {
          ptr = ctx->ParseMessage(_internal_mutable_group_address(), ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // repeated .org.e2eelab.skissm.proto.e2ee_address member_addresses = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 26)) {
          ptr -= 1;
          do {
            ptr += 1;
            ptr = ctx->ParseMessage(_internal_add_member_addresses(), ptr);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<26>(ptr));
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag == 0) || ((tag & 7) == 4)) {
          CHK_(ptr);
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* remove_group_members_request_payload::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:org.e2eelab.skissm.proto.remove_group_members_request_payload)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // .org.e2eelab.skissm.proto.e2ee_address sender_address = 1;
  if (this->_internal_has_sender_address()) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        1, _Internal::sender_address(this), target, stream);
  }

  // .org.e2eelab.skissm.proto.e2ee_address group_address = 2;
  if (this->_internal_has_group_address()) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        2, _Internal::group_address(this), target, stream);
  }

  // repeated .org.e2eelab.skissm.proto.e2ee_address member_addresses = 3;
  for (unsigned int i = 0,
      n = static_cast<unsigned int>(this->_internal_member_addresses_size()); i < n; i++) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(3, this->_internal_member_addresses(i), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:org.e2eelab.skissm.proto.remove_group_members_request_payload)
  return target;
}

size_t remove_group_members_request_payload::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:org.e2eelab.skissm.proto.remove_group_members_request_payload)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated .org.e2eelab.skissm.proto.e2ee_address member_addresses = 3;
  total_size += 1UL * this->_internal_member_addresses_size();
  for (const auto& msg : this->member_addresses_) {
    total_size +=
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(msg);
  }

  // .org.e2eelab.skissm.proto.e2ee_address sender_address = 1;
  if (this->_internal_has_sender_address()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *sender_address_);
  }

  // .org.e2eelab.skissm.proto.e2ee_address group_address = 2;
  if (this->_internal_has_group_address()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *group_address_);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData remove_group_members_request_payload::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSizeCheck,
    remove_group_members_request_payload::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*remove_group_members_request_payload::GetClassData() const { return &_class_data_; }

void remove_group_members_request_payload::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message*to,
                      const ::PROTOBUF_NAMESPACE_ID::Message&from) {
  static_cast<remove_group_members_request_payload *>(to)->MergeFrom(
      static_cast<const remove_group_members_request_payload &>(from));
}


void remove_group_members_request_payload::MergeFrom(const remove_group_members_request_payload& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:org.e2eelab.skissm.proto.remove_group_members_request_payload)
  GOOGLE_DCHECK_NE(&from, this);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  member_addresses_.MergeFrom(from.member_addresses_);
  if (from._internal_has_sender_address()) {
    _internal_mutable_sender_address()->::org::e2eelab::skissm::proto::e2ee_address::MergeFrom(from._internal_sender_address());
  }
  if (from._internal_has_group_address()) {
    _internal_mutable_group_address()->::org::e2eelab::skissm::proto::e2ee_address::MergeFrom(from._internal_group_address());
  }
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void remove_group_members_request_payload::CopyFrom(const remove_group_members_request_payload& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:org.e2eelab.skissm.proto.remove_group_members_request_payload)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool remove_group_members_request_payload::IsInitialized() const {
  return true;
}

void remove_group_members_request_payload::InternalSwap(remove_group_members_request_payload* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  member_addresses_.InternalSwap(&other->member_addresses_);
  ::PROTOBUF_NAMESPACE_ID::internal::memswap<
      PROTOBUF_FIELD_OFFSET(remove_group_members_request_payload, group_address_)
      + sizeof(remove_group_members_request_payload::group_address_)
      - PROTOBUF_FIELD_OFFSET(remove_group_members_request_payload, sender_address_)>(
          reinterpret_cast<char*>(&sender_address_),
          reinterpret_cast<char*>(&other->sender_address_));
}

::PROTOBUF_NAMESPACE_ID::Metadata remove_group_members_request_payload::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto_getter, &descriptor_table_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto_once,
      file_level_metadata_skissm_2fremove_5fgroup_5fmembers_5frequest_5fpayload_2eproto[0]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::org::e2eelab::skissm::proto::remove_group_members_request_payload* Arena::CreateMaybeMessage< ::org::e2eelab::skissm::proto::remove_group_members_request_payload >(Arena* arena) {
  return Arena::CreateMessageInternal< ::org::e2eelab::skissm::proto::remove_group_members_request_payload >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
