// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/e2ee_pre_key_bundle.proto

#include "skissm/e2ee_pre_key_bundle.pb.h"

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
constexpr e2ee_pre_key_bundle::e2ee_pre_key_bundle(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : identity_key_public_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string)
  , peer_address_(nullptr)
  , signed_pre_key_public_(nullptr)
  , one_time_pre_key_public_(nullptr){}
struct e2ee_pre_key_bundleDefaultTypeInternal {
  constexpr e2ee_pre_key_bundleDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~e2ee_pre_key_bundleDefaultTypeInternal() {}
  union {
    e2ee_pre_key_bundle _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT e2ee_pre_key_bundleDefaultTypeInternal _e2ee_pre_key_bundle_default_instance_;
}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org
static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::e2ee_pre_key_bundle, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::e2ee_pre_key_bundle, peer_address_),
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::e2ee_pre_key_bundle, identity_key_public_),
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::e2ee_pre_key_bundle, signed_pre_key_public_),
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::e2ee_pre_key_bundle, one_time_pre_key_public_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::org::e2eelab::skissm::proto::e2ee_pre_key_bundle)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::org::e2eelab::skissm::proto::_e2ee_pre_key_bundle_default_instance_),
};

const char descriptor_table_protodef_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n skissm/e2ee_pre_key_bundle.proto\022\030org."
  "e2eelab.skissm.proto\032\031skissm/e2ee_addres"
  "s.proto\032\"skissm/signed_pre_key_public.pr"
  "oto\032$skissm/one_time_pre_key_public.prot"
  "o\"\224\002\n\023e2ee_pre_key_bundle\022<\n\014peer_addres"
  "s\030\001 \001(\0132&.org.e2eelab.skissm.proto.e2ee_"
  "address\022\033\n\023identity_key_public\030\002 \001(\014\022N\n\025"
  "signed_pre_key_public\030\003 \001(\0132/.org.e2eela"
  "b.skissm.proto.signed_pre_key_public\022R\n\027"
  "one_time_pre_key_public\030\004 \001(\01321.org.e2ee"
  "lab.skissm.proto.one_time_pre_key_public"
  "B\022B\020E2eePreKeyBundleb\006proto3"
  ;
static const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable*const descriptor_table_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto_deps[3] = {
  &::descriptor_table_skissm_2fe2ee_5faddress_2eproto,
  &::descriptor_table_skissm_2fone_5ftime_5fpre_5fkey_5fpublic_2eproto,
  &::descriptor_table_skissm_2fsigned_5fpre_5fkey_5fpublic_2eproto,
};
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto = {
  false, false, 468, descriptor_table_protodef_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto, "skissm/e2ee_pre_key_bundle.proto", 
  &descriptor_table_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto_once, descriptor_table_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto_deps, 3, 1,
  schemas, file_default_instances, TableStruct_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto::offsets,
  file_level_metadata_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto, file_level_enum_descriptors_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto, file_level_service_descriptors_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable* descriptor_table_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto_getter() {
  return &descriptor_table_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY static ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptorsRunner dynamic_init_dummy_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto(&descriptor_table_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto);
namespace org {
namespace e2eelab {
namespace skissm {
namespace proto {

// ===================================================================

class e2ee_pre_key_bundle::_Internal {
 public:
  static const ::org::e2eelab::skissm::proto::e2ee_address& peer_address(const e2ee_pre_key_bundle* msg);
  static const ::org::e2eelab::skissm::proto::signed_pre_key_public& signed_pre_key_public(const e2ee_pre_key_bundle* msg);
  static const ::org::e2eelab::skissm::proto::one_time_pre_key_public& one_time_pre_key_public(const e2ee_pre_key_bundle* msg);
};

const ::org::e2eelab::skissm::proto::e2ee_address&
e2ee_pre_key_bundle::_Internal::peer_address(const e2ee_pre_key_bundle* msg) {
  return *msg->peer_address_;
}
const ::org::e2eelab::skissm::proto::signed_pre_key_public&
e2ee_pre_key_bundle::_Internal::signed_pre_key_public(const e2ee_pre_key_bundle* msg) {
  return *msg->signed_pre_key_public_;
}
const ::org::e2eelab::skissm::proto::one_time_pre_key_public&
e2ee_pre_key_bundle::_Internal::one_time_pre_key_public(const e2ee_pre_key_bundle* msg) {
  return *msg->one_time_pre_key_public_;
}
void e2ee_pre_key_bundle::clear_peer_address() {
  if (GetArenaForAllocation() == nullptr && peer_address_ != nullptr) {
    delete peer_address_;
  }
  peer_address_ = nullptr;
}
void e2ee_pre_key_bundle::clear_signed_pre_key_public() {
  if (GetArenaForAllocation() == nullptr && signed_pre_key_public_ != nullptr) {
    delete signed_pre_key_public_;
  }
  signed_pre_key_public_ = nullptr;
}
void e2ee_pre_key_bundle::clear_one_time_pre_key_public() {
  if (GetArenaForAllocation() == nullptr && one_time_pre_key_public_ != nullptr) {
    delete one_time_pre_key_public_;
  }
  one_time_pre_key_public_ = nullptr;
}
e2ee_pre_key_bundle::e2ee_pre_key_bundle(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:org.e2eelab.skissm.proto.e2ee_pre_key_bundle)
}
e2ee_pre_key_bundle::e2ee_pre_key_bundle(const e2ee_pre_key_bundle& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  identity_key_public_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_identity_key_public().empty()) {
    identity_key_public_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_identity_key_public(), 
      GetArenaForAllocation());
  }
  if (from._internal_has_peer_address()) {
    peer_address_ = new ::org::e2eelab::skissm::proto::e2ee_address(*from.peer_address_);
  } else {
    peer_address_ = nullptr;
  }
  if (from._internal_has_signed_pre_key_public()) {
    signed_pre_key_public_ = new ::org::e2eelab::skissm::proto::signed_pre_key_public(*from.signed_pre_key_public_);
  } else {
    signed_pre_key_public_ = nullptr;
  }
  if (from._internal_has_one_time_pre_key_public()) {
    one_time_pre_key_public_ = new ::org::e2eelab::skissm::proto::one_time_pre_key_public(*from.one_time_pre_key_public_);
  } else {
    one_time_pre_key_public_ = nullptr;
  }
  // @@protoc_insertion_point(copy_constructor:org.e2eelab.skissm.proto.e2ee_pre_key_bundle)
}

inline void e2ee_pre_key_bundle::SharedCtor() {
identity_key_public_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
::memset(reinterpret_cast<char*>(this) + static_cast<size_t>(
    reinterpret_cast<char*>(&peer_address_) - reinterpret_cast<char*>(this)),
    0, static_cast<size_t>(reinterpret_cast<char*>(&one_time_pre_key_public_) -
    reinterpret_cast<char*>(&peer_address_)) + sizeof(one_time_pre_key_public_));
}

e2ee_pre_key_bundle::~e2ee_pre_key_bundle() {
  // @@protoc_insertion_point(destructor:org.e2eelab.skissm.proto.e2ee_pre_key_bundle)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

inline void e2ee_pre_key_bundle::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  identity_key_public_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (this != internal_default_instance()) delete peer_address_;
  if (this != internal_default_instance()) delete signed_pre_key_public_;
  if (this != internal_default_instance()) delete one_time_pre_key_public_;
}

void e2ee_pre_key_bundle::ArenaDtor(void* object) {
  e2ee_pre_key_bundle* _this = reinterpret_cast< e2ee_pre_key_bundle* >(object);
  (void)_this;
}
void e2ee_pre_key_bundle::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void e2ee_pre_key_bundle::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void e2ee_pre_key_bundle::Clear() {
// @@protoc_insertion_point(message_clear_start:org.e2eelab.skissm.proto.e2ee_pre_key_bundle)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  identity_key_public_.ClearToEmpty();
  if (GetArenaForAllocation() == nullptr && peer_address_ != nullptr) {
    delete peer_address_;
  }
  peer_address_ = nullptr;
  if (GetArenaForAllocation() == nullptr && signed_pre_key_public_ != nullptr) {
    delete signed_pre_key_public_;
  }
  signed_pre_key_public_ = nullptr;
  if (GetArenaForAllocation() == nullptr && one_time_pre_key_public_ != nullptr) {
    delete one_time_pre_key_public_;
  }
  one_time_pre_key_public_ = nullptr;
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* e2ee_pre_key_bundle::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // .org.e2eelab.skissm.proto.e2ee_address peer_address = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          ptr = ctx->ParseMessage(_internal_mutable_peer_address(), ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // bytes identity_key_public = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 18)) {
          auto str = _internal_mutable_identity_key_public();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // .org.e2eelab.skissm.proto.signed_pre_key_public signed_pre_key_public = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 26)) {
          ptr = ctx->ParseMessage(_internal_mutable_signed_pre_key_public(), ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // .org.e2eelab.skissm.proto.one_time_pre_key_public one_time_pre_key_public = 4;
      case 4:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 34)) {
          ptr = ctx->ParseMessage(_internal_mutable_one_time_pre_key_public(), ptr);
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

::PROTOBUF_NAMESPACE_ID::uint8* e2ee_pre_key_bundle::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:org.e2eelab.skissm.proto.e2ee_pre_key_bundle)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // .org.e2eelab.skissm.proto.e2ee_address peer_address = 1;
  if (this->_internal_has_peer_address()) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        1, _Internal::peer_address(this), target, stream);
  }

  // bytes identity_key_public = 2;
  if (!this->_internal_identity_key_public().empty()) {
    target = stream->WriteBytesMaybeAliased(
        2, this->_internal_identity_key_public(), target);
  }

  // .org.e2eelab.skissm.proto.signed_pre_key_public signed_pre_key_public = 3;
  if (this->_internal_has_signed_pre_key_public()) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        3, _Internal::signed_pre_key_public(this), target, stream);
  }

  // .org.e2eelab.skissm.proto.one_time_pre_key_public one_time_pre_key_public = 4;
  if (this->_internal_has_one_time_pre_key_public()) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        4, _Internal::one_time_pre_key_public(this), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:org.e2eelab.skissm.proto.e2ee_pre_key_bundle)
  return target;
}

size_t e2ee_pre_key_bundle::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:org.e2eelab.skissm.proto.e2ee_pre_key_bundle)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // bytes identity_key_public = 2;
  if (!this->_internal_identity_key_public().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_identity_key_public());
  }

  // .org.e2eelab.skissm.proto.e2ee_address peer_address = 1;
  if (this->_internal_has_peer_address()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *peer_address_);
  }

  // .org.e2eelab.skissm.proto.signed_pre_key_public signed_pre_key_public = 3;
  if (this->_internal_has_signed_pre_key_public()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *signed_pre_key_public_);
  }

  // .org.e2eelab.skissm.proto.one_time_pre_key_public one_time_pre_key_public = 4;
  if (this->_internal_has_one_time_pre_key_public()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *one_time_pre_key_public_);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData e2ee_pre_key_bundle::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSizeCheck,
    e2ee_pre_key_bundle::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*e2ee_pre_key_bundle::GetClassData() const { return &_class_data_; }

void e2ee_pre_key_bundle::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message*to,
                      const ::PROTOBUF_NAMESPACE_ID::Message&from) {
  static_cast<e2ee_pre_key_bundle *>(to)->MergeFrom(
      static_cast<const e2ee_pre_key_bundle &>(from));
}


void e2ee_pre_key_bundle::MergeFrom(const e2ee_pre_key_bundle& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:org.e2eelab.skissm.proto.e2ee_pre_key_bundle)
  GOOGLE_DCHECK_NE(&from, this);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_identity_key_public().empty()) {
    _internal_set_identity_key_public(from._internal_identity_key_public());
  }
  if (from._internal_has_peer_address()) {
    _internal_mutable_peer_address()->::org::e2eelab::skissm::proto::e2ee_address::MergeFrom(from._internal_peer_address());
  }
  if (from._internal_has_signed_pre_key_public()) {
    _internal_mutable_signed_pre_key_public()->::org::e2eelab::skissm::proto::signed_pre_key_public::MergeFrom(from._internal_signed_pre_key_public());
  }
  if (from._internal_has_one_time_pre_key_public()) {
    _internal_mutable_one_time_pre_key_public()->::org::e2eelab::skissm::proto::one_time_pre_key_public::MergeFrom(from._internal_one_time_pre_key_public());
  }
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void e2ee_pre_key_bundle::CopyFrom(const e2ee_pre_key_bundle& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:org.e2eelab.skissm.proto.e2ee_pre_key_bundle)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool e2ee_pre_key_bundle::IsInitialized() const {
  return true;
}

void e2ee_pre_key_bundle::InternalSwap(e2ee_pre_key_bundle* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &identity_key_public_, GetArenaForAllocation(),
      &other->identity_key_public_, other->GetArenaForAllocation()
  );
  ::PROTOBUF_NAMESPACE_ID::internal::memswap<
      PROTOBUF_FIELD_OFFSET(e2ee_pre_key_bundle, one_time_pre_key_public_)
      + sizeof(e2ee_pre_key_bundle::one_time_pre_key_public_)
      - PROTOBUF_FIELD_OFFSET(e2ee_pre_key_bundle, peer_address_)>(
          reinterpret_cast<char*>(&peer_address_),
          reinterpret_cast<char*>(&other->peer_address_));
}

::PROTOBUF_NAMESPACE_ID::Metadata e2ee_pre_key_bundle::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto_getter, &descriptor_table_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto_once,
      file_level_metadata_skissm_2fe2ee_5fpre_5fkey_5fbundle_2eproto[0]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* Arena::CreateMaybeMessage< ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle >(Arena* arena) {
  return Arena::CreateMessageInternal< ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
