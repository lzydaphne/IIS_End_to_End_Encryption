// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/get_pre_key_bundle_response_payload.proto

#include "skissm/get_pre_key_bundle_response_payload.pb.h"

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
constexpr get_pre_key_bundle_response_payload::get_pre_key_bundle_response_payload(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : user_name_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string)
  , pre_key_bundle_(nullptr){}
struct get_pre_key_bundle_response_payloadDefaultTypeInternal {
  constexpr get_pre_key_bundle_response_payloadDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~get_pre_key_bundle_response_payloadDefaultTypeInternal() {}
  union {
    get_pre_key_bundle_response_payload _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT get_pre_key_bundle_response_payloadDefaultTypeInternal _get_pre_key_bundle_response_payload_default_instance_;
}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org
static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::get_pre_key_bundle_response_payload, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::get_pre_key_bundle_response_payload, user_name_),
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::get_pre_key_bundle_response_payload, pre_key_bundle_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::org::e2eelab::skissm::proto::get_pre_key_bundle_response_payload)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::org::e2eelab::skissm::proto::_get_pre_key_bundle_response_payload_default_instance_),
};

const char descriptor_table_protodef_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n0skissm/get_pre_key_bundle_response_pay"
  "load.proto\022\030org.e2eelab.skissm.proto\032 sk"
  "issm/e2ee_pre_key_bundle.proto\"\177\n#get_pr"
  "e_key_bundle_response_payload\022\021\n\tuser_na"
  "me\030\001 \001(\014\022E\n\016pre_key_bundle\030\002 \001(\0132-.org.e"
  "2eelab.skissm.proto.e2ee_pre_key_bundleB"
  " B\036GetPreKeyBundleResponsePayloadb\006proto"
  "3"
  ;
static const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable*const descriptor_table_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto_deps[1] = {
  &::descriptor_table_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto,
};
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto = {
  false, false, 281, descriptor_table_protodef_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto, "skissm/get_pre_key_bundle_response_payload.proto", 
  &descriptor_table_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto_once, descriptor_table_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto_deps, 1, 1,
  schemas, file_default_instances, TableStruct_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto::offsets,
  file_level_metadata_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto, file_level_enum_descriptors_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto, file_level_service_descriptors_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable* descriptor_table_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto_getter() {
  return &descriptor_table_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY static ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptorsRunner dynamic_init_dummy_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto(&descriptor_table_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto);
namespace org {
namespace e2eelab {
namespace skissm {
namespace proto {

// ===================================================================

class get_pre_key_bundle_response_payload::_Internal {
 public:
  static const ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle& pre_key_bundle(const get_pre_key_bundle_response_payload* msg);
};

const ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle&
get_pre_key_bundle_response_payload::_Internal::pre_key_bundle(const get_pre_key_bundle_response_payload* msg) {
  return *msg->pre_key_bundle_;
}
void get_pre_key_bundle_response_payload::clear_pre_key_bundle() {
  if (GetArenaForAllocation() == nullptr && pre_key_bundle_ != nullptr) {
    delete pre_key_bundle_;
  }
  pre_key_bundle_ = nullptr;
}
get_pre_key_bundle_response_payload::get_pre_key_bundle_response_payload(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload)
}
get_pre_key_bundle_response_payload::get_pre_key_bundle_response_payload(const get_pre_key_bundle_response_payload& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  user_name_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_user_name().empty()) {
    user_name_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_user_name(), 
      GetArenaForAllocation());
  }
  if (from._internal_has_pre_key_bundle()) {
    pre_key_bundle_ = new ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle(*from.pre_key_bundle_);
  } else {
    pre_key_bundle_ = nullptr;
  }
  // @@protoc_insertion_point(copy_constructor:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload)
}

inline void get_pre_key_bundle_response_payload::SharedCtor() {
user_name_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
pre_key_bundle_ = nullptr;
}

get_pre_key_bundle_response_payload::~get_pre_key_bundle_response_payload() {
  // @@protoc_insertion_point(destructor:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

inline void get_pre_key_bundle_response_payload::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  user_name_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (this != internal_default_instance()) delete pre_key_bundle_;
}

void get_pre_key_bundle_response_payload::ArenaDtor(void* object) {
  get_pre_key_bundle_response_payload* _this = reinterpret_cast< get_pre_key_bundle_response_payload* >(object);
  (void)_this;
}
void get_pre_key_bundle_response_payload::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void get_pre_key_bundle_response_payload::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void get_pre_key_bundle_response_payload::Clear() {
// @@protoc_insertion_point(message_clear_start:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  user_name_.ClearToEmpty();
  if (GetArenaForAllocation() == nullptr && pre_key_bundle_ != nullptr) {
    delete pre_key_bundle_;
  }
  pre_key_bundle_ = nullptr;
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* get_pre_key_bundle_response_payload::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // bytes user_name = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          auto str = _internal_mutable_user_name();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // .org.e2eelab.skissm.proto.e2ee_pre_key_bundle pre_key_bundle = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 18)) {
          ptr = ctx->ParseMessage(_internal_mutable_pre_key_bundle(), ptr);
          CHK_(ptr);
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

::PROTOBUF_NAMESPACE_ID::uint8* get_pre_key_bundle_response_payload::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // bytes user_name = 1;
  if (!this->_internal_user_name().empty()) {
    target = stream->WriteBytesMaybeAliased(
        1, this->_internal_user_name(), target);
  }

  // .org.e2eelab.skissm.proto.e2ee_pre_key_bundle pre_key_bundle = 2;
  if (this->_internal_has_pre_key_bundle()) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        2, _Internal::pre_key_bundle(this), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload)
  return target;
}

size_t get_pre_key_bundle_response_payload::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // bytes user_name = 1;
  if (!this->_internal_user_name().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_user_name());
  }

  // .org.e2eelab.skissm.proto.e2ee_pre_key_bundle pre_key_bundle = 2;
  if (this->_internal_has_pre_key_bundle()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *pre_key_bundle_);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData get_pre_key_bundle_response_payload::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSizeCheck,
    get_pre_key_bundle_response_payload::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*get_pre_key_bundle_response_payload::GetClassData() const { return &_class_data_; }

void get_pre_key_bundle_response_payload::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message*to,
                      const ::PROTOBUF_NAMESPACE_ID::Message&from) {
  static_cast<get_pre_key_bundle_response_payload *>(to)->MergeFrom(
      static_cast<const get_pre_key_bundle_response_payload &>(from));
}


void get_pre_key_bundle_response_payload::MergeFrom(const get_pre_key_bundle_response_payload& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload)
  GOOGLE_DCHECK_NE(&from, this);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_user_name().empty()) {
    _internal_set_user_name(from._internal_user_name());
  }
  if (from._internal_has_pre_key_bundle()) {
    _internal_mutable_pre_key_bundle()->::org::e2eelab::skissm::proto::e2ee_pre_key_bundle::MergeFrom(from._internal_pre_key_bundle());
  }
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void get_pre_key_bundle_response_payload::CopyFrom(const get_pre_key_bundle_response_payload& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool get_pre_key_bundle_response_payload::IsInitialized() const {
  return true;
}

void get_pre_key_bundle_response_payload::InternalSwap(get_pre_key_bundle_response_payload* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &user_name_, GetArenaForAllocation(),
      &other->user_name_, other->GetArenaForAllocation()
  );
  swap(pre_key_bundle_, other->pre_key_bundle_);
}

::PROTOBUF_NAMESPACE_ID::Metadata get_pre_key_bundle_response_payload::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto_getter, &descriptor_table_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto_once,
      file_level_metadata_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto[0]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::org::e2eelab::skissm::proto::get_pre_key_bundle_response_payload* Arena::CreateMaybeMessage< ::org::e2eelab::skissm::proto::get_pre_key_bundle_response_payload >(Arena* arena) {
  return Arena::CreateMessageInternal< ::org::e2eelab::skissm::proto::get_pre_key_bundle_response_payload >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
