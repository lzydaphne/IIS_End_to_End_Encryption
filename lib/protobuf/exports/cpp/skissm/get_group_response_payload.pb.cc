// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/get_group_response_payload.proto

#include "skissm/get_group_response_payload.pb.h"

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
constexpr get_group_response_payload::get_group_response_payload(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : member_addresses_()
  , group_name_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string){}
struct get_group_response_payloadDefaultTypeInternal {
  constexpr get_group_response_payloadDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~get_group_response_payloadDefaultTypeInternal() {}
  union {
    get_group_response_payload _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT get_group_response_payloadDefaultTypeInternal _get_group_response_payload_default_instance_;
}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org
static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::get_group_response_payload, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::get_group_response_payload, group_name_),
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::get_group_response_payload, member_addresses_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::org::e2eelab::skissm::proto::get_group_response_payload)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::org::e2eelab::skissm::proto::_get_group_response_payload_default_instance_),
};

const char descriptor_table_protodef_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\'skissm/get_group_response_payload.prot"
  "o\022\030org.e2eelab.skissm.proto\032\031skissm/e2ee"
  "_address.proto\"r\n\032get_group_response_pay"
  "load\022\022\n\ngroup_name\030\001 \001(\014\022@\n\020member_addre"
  "sses\030\002 \003(\0132&.org.e2eelab.skissm.proto.e2"
  "ee_addressB\031B\027GetGroupResponsePayloadb\006p"
  "roto3"
  ;
static const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable*const descriptor_table_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto_deps[1] = {
  &::descriptor_table_skissm_2fe2ee_5faddress_2eproto,
};
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto = {
  false, false, 245, descriptor_table_protodef_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto, "skissm/get_group_response_payload.proto", 
  &descriptor_table_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto_once, descriptor_table_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto_deps, 1, 1,
  schemas, file_default_instances, TableStruct_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto::offsets,
  file_level_metadata_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto, file_level_enum_descriptors_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto, file_level_service_descriptors_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable* descriptor_table_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto_getter() {
  return &descriptor_table_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY static ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptorsRunner dynamic_init_dummy_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto(&descriptor_table_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto);
namespace org {
namespace e2eelab {
namespace skissm {
namespace proto {

// ===================================================================

class get_group_response_payload::_Internal {
 public:
};

void get_group_response_payload::clear_member_addresses() {
  member_addresses_.Clear();
}
get_group_response_payload::get_group_response_payload(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned),
  member_addresses_(arena) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:org.e2eelab.skissm.proto.get_group_response_payload)
}
get_group_response_payload::get_group_response_payload(const get_group_response_payload& from)
  : ::PROTOBUF_NAMESPACE_ID::Message(),
      member_addresses_(from.member_addresses_) {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  group_name_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_group_name().empty()) {
    group_name_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_group_name(), 
      GetArenaForAllocation());
  }
  // @@protoc_insertion_point(copy_constructor:org.e2eelab.skissm.proto.get_group_response_payload)
}

inline void get_group_response_payload::SharedCtor() {
group_name_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

get_group_response_payload::~get_group_response_payload() {
  // @@protoc_insertion_point(destructor:org.e2eelab.skissm.proto.get_group_response_payload)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

inline void get_group_response_payload::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  group_name_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

void get_group_response_payload::ArenaDtor(void* object) {
  get_group_response_payload* _this = reinterpret_cast< get_group_response_payload* >(object);
  (void)_this;
}
void get_group_response_payload::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void get_group_response_payload::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void get_group_response_payload::Clear() {
// @@protoc_insertion_point(message_clear_start:org.e2eelab.skissm.proto.get_group_response_payload)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  member_addresses_.Clear();
  group_name_.ClearToEmpty();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* get_group_response_payload::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // bytes group_name = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          auto str = _internal_mutable_group_name();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // repeated .org.e2eelab.skissm.proto.e2ee_address member_addresses = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 18)) {
          ptr -= 1;
          do {
            ptr += 1;
            ptr = ctx->ParseMessage(_internal_add_member_addresses(), ptr);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<18>(ptr));
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

::PROTOBUF_NAMESPACE_ID::uint8* get_group_response_payload::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:org.e2eelab.skissm.proto.get_group_response_payload)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // bytes group_name = 1;
  if (!this->_internal_group_name().empty()) {
    target = stream->WriteBytesMaybeAliased(
        1, this->_internal_group_name(), target);
  }

  // repeated .org.e2eelab.skissm.proto.e2ee_address member_addresses = 2;
  for (unsigned int i = 0,
      n = static_cast<unsigned int>(this->_internal_member_addresses_size()); i < n; i++) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(2, this->_internal_member_addresses(i), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:org.e2eelab.skissm.proto.get_group_response_payload)
  return target;
}

size_t get_group_response_payload::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:org.e2eelab.skissm.proto.get_group_response_payload)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated .org.e2eelab.skissm.proto.e2ee_address member_addresses = 2;
  total_size += 1UL * this->_internal_member_addresses_size();
  for (const auto& msg : this->member_addresses_) {
    total_size +=
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(msg);
  }

  // bytes group_name = 1;
  if (!this->_internal_group_name().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_group_name());
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData get_group_response_payload::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSizeCheck,
    get_group_response_payload::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*get_group_response_payload::GetClassData() const { return &_class_data_; }

void get_group_response_payload::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message*to,
                      const ::PROTOBUF_NAMESPACE_ID::Message&from) {
  static_cast<get_group_response_payload *>(to)->MergeFrom(
      static_cast<const get_group_response_payload &>(from));
}


void get_group_response_payload::MergeFrom(const get_group_response_payload& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:org.e2eelab.skissm.proto.get_group_response_payload)
  GOOGLE_DCHECK_NE(&from, this);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  member_addresses_.MergeFrom(from.member_addresses_);
  if (!from._internal_group_name().empty()) {
    _internal_set_group_name(from._internal_group_name());
  }
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void get_group_response_payload::CopyFrom(const get_group_response_payload& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:org.e2eelab.skissm.proto.get_group_response_payload)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool get_group_response_payload::IsInitialized() const {
  return true;
}

void get_group_response_payload::InternalSwap(get_group_response_payload* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  member_addresses_.InternalSwap(&other->member_addresses_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &group_name_, GetArenaForAllocation(),
      &other->group_name_, other->GetArenaForAllocation()
  );
}

::PROTOBUF_NAMESPACE_ID::Metadata get_group_response_payload::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto_getter, &descriptor_table_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto_once,
      file_level_metadata_skissm_2fget_5fgroup_5fresponse_5fpayload_2eproto[0]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::org::e2eelab::skissm::proto::get_group_response_payload* Arena::CreateMaybeMessage< ::org::e2eelab::skissm::proto::get_group_response_payload >(Arena* arena) {
  return Arena::CreateMessageInternal< ::org::e2eelab::skissm::proto::get_group_response_payload >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
