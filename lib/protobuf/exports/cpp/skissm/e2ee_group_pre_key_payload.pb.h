// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/e2ee_group_pre_key_payload.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_skissm_2fe2ee_5fgroup_5fpre_5fkey_5fpayload_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_skissm_2fe2ee_5fgroup_5fpre_5fkey_5fpayload_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3017000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3017003 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
#include "skissm/e2ee_address.pb.h"
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_skissm_2fe2ee_5fgroup_5fpre_5fkey_5fpayload_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_skissm_2fe2ee_5fgroup_5fpre_5fkey_5fpayload_2eproto {
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTableField entries[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::AuxiliaryParseTableField aux[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTable schema[1]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::FieldMetadata field_metadata[];
  static const ::PROTOBUF_NAMESPACE_ID::internal::SerializationTable serialization_table[];
  static const ::PROTOBUF_NAMESPACE_ID::uint32 offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fe2ee_5fgroup_5fpre_5fkey_5fpayload_2eproto;
namespace org {
namespace e2eelab {
namespace skissm {
namespace proto {
class e2ee_group_pre_key_payload;
struct e2ee_group_pre_key_payloadDefaultTypeInternal;
extern e2ee_group_pre_key_payloadDefaultTypeInternal _e2ee_group_pre_key_payload_default_instance_;
}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org
PROTOBUF_NAMESPACE_OPEN
template<> ::org::e2eelab::skissm::proto::e2ee_group_pre_key_payload* Arena::CreateMaybeMessage<::org::e2eelab::skissm::proto::e2ee_group_pre_key_payload>(Arena*);
PROTOBUF_NAMESPACE_CLOSE
namespace org {
namespace e2eelab {
namespace skissm {
namespace proto {

// ===================================================================

class e2ee_group_pre_key_payload final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload) */ {
 public:
  inline e2ee_group_pre_key_payload() : e2ee_group_pre_key_payload(nullptr) {}
  ~e2ee_group_pre_key_payload() override;
  explicit constexpr e2ee_group_pre_key_payload(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  e2ee_group_pre_key_payload(const e2ee_group_pre_key_payload& from);
  e2ee_group_pre_key_payload(e2ee_group_pre_key_payload&& from) noexcept
    : e2ee_group_pre_key_payload() {
    *this = ::std::move(from);
  }

  inline e2ee_group_pre_key_payload& operator=(const e2ee_group_pre_key_payload& from) {
    CopyFrom(from);
    return *this;
  }
  inline e2ee_group_pre_key_payload& operator=(e2ee_group_pre_key_payload&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const e2ee_group_pre_key_payload& default_instance() {
    return *internal_default_instance();
  }
  static inline const e2ee_group_pre_key_payload* internal_default_instance() {
    return reinterpret_cast<const e2ee_group_pre_key_payload*>(
               &_e2ee_group_pre_key_payload_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(e2ee_group_pre_key_payload& a, e2ee_group_pre_key_payload& b) {
    a.Swap(&b);
  }
  inline void Swap(e2ee_group_pre_key_payload* other) {
    if (other == this) return;
    if (GetOwningArena() == other->GetOwningArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(e2ee_group_pre_key_payload* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline e2ee_group_pre_key_payload* New() const final {
    return new e2ee_group_pre_key_payload();
  }

  e2ee_group_pre_key_payload* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<e2ee_group_pre_key_payload>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const e2ee_group_pre_key_payload& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom(const e2ee_group_pre_key_payload& from);
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message*to, const ::PROTOBUF_NAMESPACE_ID::Message&from);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(e2ee_group_pre_key_payload* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "org.e2eelab.skissm.proto.e2ee_group_pre_key_payload";
  }
  protected:
  explicit e2ee_group_pre_key_payload(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kMemberAddressesFieldNumber = 5,
    kSessionIdFieldNumber = 2,
    kOldSessionIdFieldNumber = 3,
    kChainKeyFieldNumber = 7,
    kSignaturePublicKeyFieldNumber = 8,
    kGroupAddressFieldNumber = 4,
    kVersionFieldNumber = 1,
    kSequenceFieldNumber = 6,
  };
  // repeated .org.e2eelab.skissm.proto.e2ee_address member_addresses = 5;
  int member_addresses_size() const;
  private:
  int _internal_member_addresses_size() const;
  public:
  void clear_member_addresses();
  ::org::e2eelab::skissm::proto::e2ee_address* mutable_member_addresses(int index);
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::org::e2eelab::skissm::proto::e2ee_address >*
      mutable_member_addresses();
  private:
  const ::org::e2eelab::skissm::proto::e2ee_address& _internal_member_addresses(int index) const;
  ::org::e2eelab::skissm::proto::e2ee_address* _internal_add_member_addresses();
  public:
  const ::org::e2eelab::skissm::proto::e2ee_address& member_addresses(int index) const;
  ::org::e2eelab::skissm::proto::e2ee_address* add_member_addresses();
  const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::org::e2eelab::skissm::proto::e2ee_address >&
      member_addresses() const;

  // bytes session_id = 2;
  void clear_session_id();
  const std::string& session_id() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_session_id(ArgT0&& arg0, ArgT... args);
  std::string* mutable_session_id();
  PROTOBUF_MUST_USE_RESULT std::string* release_session_id();
  void set_allocated_session_id(std::string* session_id);
  private:
  const std::string& _internal_session_id() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_session_id(const std::string& value);
  std::string* _internal_mutable_session_id();
  public:

  // bytes old_session_id = 3;
  void clear_old_session_id();
  const std::string& old_session_id() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_old_session_id(ArgT0&& arg0, ArgT... args);
  std::string* mutable_old_session_id();
  PROTOBUF_MUST_USE_RESULT std::string* release_old_session_id();
  void set_allocated_old_session_id(std::string* old_session_id);
  private:
  const std::string& _internal_old_session_id() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_old_session_id(const std::string& value);
  std::string* _internal_mutable_old_session_id();
  public:

  // bytes chain_key = 7;
  void clear_chain_key();
  const std::string& chain_key() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_chain_key(ArgT0&& arg0, ArgT... args);
  std::string* mutable_chain_key();
  PROTOBUF_MUST_USE_RESULT std::string* release_chain_key();
  void set_allocated_chain_key(std::string* chain_key);
  private:
  const std::string& _internal_chain_key() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_chain_key(const std::string& value);
  std::string* _internal_mutable_chain_key();
  public:

  // bytes signature_public_key = 8;
  void clear_signature_public_key();
  const std::string& signature_public_key() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_signature_public_key(ArgT0&& arg0, ArgT... args);
  std::string* mutable_signature_public_key();
  PROTOBUF_MUST_USE_RESULT std::string* release_signature_public_key();
  void set_allocated_signature_public_key(std::string* signature_public_key);
  private:
  const std::string& _internal_signature_public_key() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_signature_public_key(const std::string& value);
  std::string* _internal_mutable_signature_public_key();
  public:

  // .org.e2eelab.skissm.proto.e2ee_address group_address = 4;
  bool has_group_address() const;
  private:
  bool _internal_has_group_address() const;
  public:
  void clear_group_address();
  const ::org::e2eelab::skissm::proto::e2ee_address& group_address() const;
  PROTOBUF_MUST_USE_RESULT ::org::e2eelab::skissm::proto::e2ee_address* release_group_address();
  ::org::e2eelab::skissm::proto::e2ee_address* mutable_group_address();
  void set_allocated_group_address(::org::e2eelab::skissm::proto::e2ee_address* group_address);
  private:
  const ::org::e2eelab::skissm::proto::e2ee_address& _internal_group_address() const;
  ::org::e2eelab::skissm::proto::e2ee_address* _internal_mutable_group_address();
  public:
  void unsafe_arena_set_allocated_group_address(
      ::org::e2eelab::skissm::proto::e2ee_address* group_address);
  ::org::e2eelab::skissm::proto::e2ee_address* unsafe_arena_release_group_address();

  // uint32 version = 1;
  void clear_version();
  ::PROTOBUF_NAMESPACE_ID::uint32 version() const;
  void set_version(::PROTOBUF_NAMESPACE_ID::uint32 value);
  private:
  ::PROTOBUF_NAMESPACE_ID::uint32 _internal_version() const;
  void _internal_set_version(::PROTOBUF_NAMESPACE_ID::uint32 value);
  public:

  // uint32 sequence = 6;
  void clear_sequence();
  ::PROTOBUF_NAMESPACE_ID::uint32 sequence() const;
  void set_sequence(::PROTOBUF_NAMESPACE_ID::uint32 value);
  private:
  ::PROTOBUF_NAMESPACE_ID::uint32 _internal_sequence() const;
  void _internal_set_sequence(::PROTOBUF_NAMESPACE_ID::uint32 value);
  public:

  // @@protoc_insertion_point(class_scope:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::org::e2eelab::skissm::proto::e2ee_address > member_addresses_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr session_id_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr old_session_id_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr chain_key_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr signature_public_key_;
  ::org::e2eelab::skissm::proto::e2ee_address* group_address_;
  ::PROTOBUF_NAMESPACE_ID::uint32 version_;
  ::PROTOBUF_NAMESPACE_ID::uint32 sequence_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_skissm_2fe2ee_5fgroup_5fpre_5fkey_5fpayload_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// e2ee_group_pre_key_payload

// uint32 version = 1;
inline void e2ee_group_pre_key_payload::clear_version() {
  version_ = 0u;
}
inline ::PROTOBUF_NAMESPACE_ID::uint32 e2ee_group_pre_key_payload::_internal_version() const {
  return version_;
}
inline ::PROTOBUF_NAMESPACE_ID::uint32 e2ee_group_pre_key_payload::version() const {
  // @@protoc_insertion_point(field_get:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.version)
  return _internal_version();
}
inline void e2ee_group_pre_key_payload::_internal_set_version(::PROTOBUF_NAMESPACE_ID::uint32 value) {
  
  version_ = value;
}
inline void e2ee_group_pre_key_payload::set_version(::PROTOBUF_NAMESPACE_ID::uint32 value) {
  _internal_set_version(value);
  // @@protoc_insertion_point(field_set:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.version)
}

// bytes session_id = 2;
inline void e2ee_group_pre_key_payload::clear_session_id() {
  session_id_.ClearToEmpty();
}
inline const std::string& e2ee_group_pre_key_payload::session_id() const {
  // @@protoc_insertion_point(field_get:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.session_id)
  return _internal_session_id();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void e2ee_group_pre_key_payload::set_session_id(ArgT0&& arg0, ArgT... args) {
 
 session_id_.SetBytes(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.session_id)
}
inline std::string* e2ee_group_pre_key_payload::mutable_session_id() {
  std::string* _s = _internal_mutable_session_id();
  // @@protoc_insertion_point(field_mutable:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.session_id)
  return _s;
}
inline const std::string& e2ee_group_pre_key_payload::_internal_session_id() const {
  return session_id_.Get();
}
inline void e2ee_group_pre_key_payload::_internal_set_session_id(const std::string& value) {
  
  session_id_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* e2ee_group_pre_key_payload::_internal_mutable_session_id() {
  
  return session_id_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* e2ee_group_pre_key_payload::release_session_id() {
  // @@protoc_insertion_point(field_release:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.session_id)
  return session_id_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void e2ee_group_pre_key_payload::set_allocated_session_id(std::string* session_id) {
  if (session_id != nullptr) {
    
  } else {
    
  }
  session_id_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), session_id,
      GetArenaForAllocation());
  // @@protoc_insertion_point(field_set_allocated:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.session_id)
}

// bytes old_session_id = 3;
inline void e2ee_group_pre_key_payload::clear_old_session_id() {
  old_session_id_.ClearToEmpty();
}
inline const std::string& e2ee_group_pre_key_payload::old_session_id() const {
  // @@protoc_insertion_point(field_get:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.old_session_id)
  return _internal_old_session_id();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void e2ee_group_pre_key_payload::set_old_session_id(ArgT0&& arg0, ArgT... args) {
 
 old_session_id_.SetBytes(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.old_session_id)
}
inline std::string* e2ee_group_pre_key_payload::mutable_old_session_id() {
  std::string* _s = _internal_mutable_old_session_id();
  // @@protoc_insertion_point(field_mutable:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.old_session_id)
  return _s;
}
inline const std::string& e2ee_group_pre_key_payload::_internal_old_session_id() const {
  return old_session_id_.Get();
}
inline void e2ee_group_pre_key_payload::_internal_set_old_session_id(const std::string& value) {
  
  old_session_id_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* e2ee_group_pre_key_payload::_internal_mutable_old_session_id() {
  
  return old_session_id_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* e2ee_group_pre_key_payload::release_old_session_id() {
  // @@protoc_insertion_point(field_release:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.old_session_id)
  return old_session_id_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void e2ee_group_pre_key_payload::set_allocated_old_session_id(std::string* old_session_id) {
  if (old_session_id != nullptr) {
    
  } else {
    
  }
  old_session_id_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), old_session_id,
      GetArenaForAllocation());
  // @@protoc_insertion_point(field_set_allocated:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.old_session_id)
}

// .org.e2eelab.skissm.proto.e2ee_address group_address = 4;
inline bool e2ee_group_pre_key_payload::_internal_has_group_address() const {
  return this != internal_default_instance() && group_address_ != nullptr;
}
inline bool e2ee_group_pre_key_payload::has_group_address() const {
  return _internal_has_group_address();
}
inline const ::org::e2eelab::skissm::proto::e2ee_address& e2ee_group_pre_key_payload::_internal_group_address() const {
  const ::org::e2eelab::skissm::proto::e2ee_address* p = group_address_;
  return p != nullptr ? *p : reinterpret_cast<const ::org::e2eelab::skissm::proto::e2ee_address&>(
      ::org::e2eelab::skissm::proto::_e2ee_address_default_instance_);
}
inline const ::org::e2eelab::skissm::proto::e2ee_address& e2ee_group_pre_key_payload::group_address() const {
  // @@protoc_insertion_point(field_get:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.group_address)
  return _internal_group_address();
}
inline void e2ee_group_pre_key_payload::unsafe_arena_set_allocated_group_address(
    ::org::e2eelab::skissm::proto::e2ee_address* group_address) {
  if (GetArenaForAllocation() == nullptr) {
    delete reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(group_address_);
  }
  group_address_ = group_address;
  if (group_address) {
    
  } else {
    
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.group_address)
}
inline ::org::e2eelab::skissm::proto::e2ee_address* e2ee_group_pre_key_payload::release_group_address() {
  
  ::org::e2eelab::skissm::proto::e2ee_address* temp = group_address_;
  group_address_ = nullptr;
#ifdef PROTOBUF_FORCE_COPY_IN_RELEASE
  auto* old =  reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(temp);
  temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  if (GetArenaForAllocation() == nullptr) { delete old; }
#else  // PROTOBUF_FORCE_COPY_IN_RELEASE
  if (GetArenaForAllocation() != nullptr) {
    temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  }
#endif  // !PROTOBUF_FORCE_COPY_IN_RELEASE
  return temp;
}
inline ::org::e2eelab::skissm::proto::e2ee_address* e2ee_group_pre_key_payload::unsafe_arena_release_group_address() {
  // @@protoc_insertion_point(field_release:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.group_address)
  
  ::org::e2eelab::skissm::proto::e2ee_address* temp = group_address_;
  group_address_ = nullptr;
  return temp;
}
inline ::org::e2eelab::skissm::proto::e2ee_address* e2ee_group_pre_key_payload::_internal_mutable_group_address() {
  
  if (group_address_ == nullptr) {
    auto* p = CreateMaybeMessage<::org::e2eelab::skissm::proto::e2ee_address>(GetArenaForAllocation());
    group_address_ = p;
  }
  return group_address_;
}
inline ::org::e2eelab::skissm::proto::e2ee_address* e2ee_group_pre_key_payload::mutable_group_address() {
  ::org::e2eelab::skissm::proto::e2ee_address* _msg = _internal_mutable_group_address();
  // @@protoc_insertion_point(field_mutable:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.group_address)
  return _msg;
}
inline void e2ee_group_pre_key_payload::set_allocated_group_address(::org::e2eelab::skissm::proto::e2ee_address* group_address) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  if (message_arena == nullptr) {
    delete reinterpret_cast< ::PROTOBUF_NAMESPACE_ID::MessageLite*>(group_address_);
  }
  if (group_address) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
        ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper<
            ::PROTOBUF_NAMESPACE_ID::MessageLite>::GetOwningArena(
                reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(group_address));
    if (message_arena != submessage_arena) {
      group_address = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, group_address, submessage_arena);
    }
    
  } else {
    
  }
  group_address_ = group_address;
  // @@protoc_insertion_point(field_set_allocated:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.group_address)
}

// repeated .org.e2eelab.skissm.proto.e2ee_address member_addresses = 5;
inline int e2ee_group_pre_key_payload::_internal_member_addresses_size() const {
  return member_addresses_.size();
}
inline int e2ee_group_pre_key_payload::member_addresses_size() const {
  return _internal_member_addresses_size();
}
inline ::org::e2eelab::skissm::proto::e2ee_address* e2ee_group_pre_key_payload::mutable_member_addresses(int index) {
  // @@protoc_insertion_point(field_mutable:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.member_addresses)
  return member_addresses_.Mutable(index);
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::org::e2eelab::skissm::proto::e2ee_address >*
e2ee_group_pre_key_payload::mutable_member_addresses() {
  // @@protoc_insertion_point(field_mutable_list:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.member_addresses)
  return &member_addresses_;
}
inline const ::org::e2eelab::skissm::proto::e2ee_address& e2ee_group_pre_key_payload::_internal_member_addresses(int index) const {
  return member_addresses_.Get(index);
}
inline const ::org::e2eelab::skissm::proto::e2ee_address& e2ee_group_pre_key_payload::member_addresses(int index) const {
  // @@protoc_insertion_point(field_get:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.member_addresses)
  return _internal_member_addresses(index);
}
inline ::org::e2eelab::skissm::proto::e2ee_address* e2ee_group_pre_key_payload::_internal_add_member_addresses() {
  return member_addresses_.Add();
}
inline ::org::e2eelab::skissm::proto::e2ee_address* e2ee_group_pre_key_payload::add_member_addresses() {
  ::org::e2eelab::skissm::proto::e2ee_address* _add = _internal_add_member_addresses();
  // @@protoc_insertion_point(field_add:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.member_addresses)
  return _add;
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::org::e2eelab::skissm::proto::e2ee_address >&
e2ee_group_pre_key_payload::member_addresses() const {
  // @@protoc_insertion_point(field_list:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.member_addresses)
  return member_addresses_;
}

// uint32 sequence = 6;
inline void e2ee_group_pre_key_payload::clear_sequence() {
  sequence_ = 0u;
}
inline ::PROTOBUF_NAMESPACE_ID::uint32 e2ee_group_pre_key_payload::_internal_sequence() const {
  return sequence_;
}
inline ::PROTOBUF_NAMESPACE_ID::uint32 e2ee_group_pre_key_payload::sequence() const {
  // @@protoc_insertion_point(field_get:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.sequence)
  return _internal_sequence();
}
inline void e2ee_group_pre_key_payload::_internal_set_sequence(::PROTOBUF_NAMESPACE_ID::uint32 value) {
  
  sequence_ = value;
}
inline void e2ee_group_pre_key_payload::set_sequence(::PROTOBUF_NAMESPACE_ID::uint32 value) {
  _internal_set_sequence(value);
  // @@protoc_insertion_point(field_set:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.sequence)
}

// bytes chain_key = 7;
inline void e2ee_group_pre_key_payload::clear_chain_key() {
  chain_key_.ClearToEmpty();
}
inline const std::string& e2ee_group_pre_key_payload::chain_key() const {
  // @@protoc_insertion_point(field_get:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.chain_key)
  return _internal_chain_key();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void e2ee_group_pre_key_payload::set_chain_key(ArgT0&& arg0, ArgT... args) {
 
 chain_key_.SetBytes(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.chain_key)
}
inline std::string* e2ee_group_pre_key_payload::mutable_chain_key() {
  std::string* _s = _internal_mutable_chain_key();
  // @@protoc_insertion_point(field_mutable:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.chain_key)
  return _s;
}
inline const std::string& e2ee_group_pre_key_payload::_internal_chain_key() const {
  return chain_key_.Get();
}
inline void e2ee_group_pre_key_payload::_internal_set_chain_key(const std::string& value) {
  
  chain_key_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* e2ee_group_pre_key_payload::_internal_mutable_chain_key() {
  
  return chain_key_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* e2ee_group_pre_key_payload::release_chain_key() {
  // @@protoc_insertion_point(field_release:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.chain_key)
  return chain_key_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void e2ee_group_pre_key_payload::set_allocated_chain_key(std::string* chain_key) {
  if (chain_key != nullptr) {
    
  } else {
    
  }
  chain_key_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), chain_key,
      GetArenaForAllocation());
  // @@protoc_insertion_point(field_set_allocated:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.chain_key)
}

// bytes signature_public_key = 8;
inline void e2ee_group_pre_key_payload::clear_signature_public_key() {
  signature_public_key_.ClearToEmpty();
}
inline const std::string& e2ee_group_pre_key_payload::signature_public_key() const {
  // @@protoc_insertion_point(field_get:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.signature_public_key)
  return _internal_signature_public_key();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void e2ee_group_pre_key_payload::set_signature_public_key(ArgT0&& arg0, ArgT... args) {
 
 signature_public_key_.SetBytes(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.signature_public_key)
}
inline std::string* e2ee_group_pre_key_payload::mutable_signature_public_key() {
  std::string* _s = _internal_mutable_signature_public_key();
  // @@protoc_insertion_point(field_mutable:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.signature_public_key)
  return _s;
}
inline const std::string& e2ee_group_pre_key_payload::_internal_signature_public_key() const {
  return signature_public_key_.Get();
}
inline void e2ee_group_pre_key_payload::_internal_set_signature_public_key(const std::string& value) {
  
  signature_public_key_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* e2ee_group_pre_key_payload::_internal_mutable_signature_public_key() {
  
  return signature_public_key_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* e2ee_group_pre_key_payload::release_signature_public_key() {
  // @@protoc_insertion_point(field_release:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.signature_public_key)
  return signature_public_key_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void e2ee_group_pre_key_payload::set_allocated_signature_public_key(std::string* signature_public_key) {
  if (signature_public_key != nullptr) {
    
  } else {
    
  }
  signature_public_key_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), signature_public_key,
      GetArenaForAllocation());
  // @@protoc_insertion_point(field_set_allocated:org.e2eelab.skissm.proto.e2ee_group_pre_key_payload.signature_public_key)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__

// @@protoc_insertion_point(namespace_scope)

}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org

// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_skissm_2fe2ee_5fgroup_5fpre_5fkey_5fpayload_2eproto
