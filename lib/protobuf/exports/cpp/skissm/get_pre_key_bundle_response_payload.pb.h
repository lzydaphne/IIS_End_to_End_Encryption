// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/get_pre_key_bundle_response_payload.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto

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
#include "skissm/e2ee_pre_key_bundle.pb.h"
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto {
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
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto;
namespace org {
namespace e2eelab {
namespace skissm {
namespace proto {
class get_pre_key_bundle_response_payload;
struct get_pre_key_bundle_response_payloadDefaultTypeInternal;
extern get_pre_key_bundle_response_payloadDefaultTypeInternal _get_pre_key_bundle_response_payload_default_instance_;
}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org
PROTOBUF_NAMESPACE_OPEN
template<> ::org::e2eelab::skissm::proto::get_pre_key_bundle_response_payload* Arena::CreateMaybeMessage<::org::e2eelab::skissm::proto::get_pre_key_bundle_response_payload>(Arena*);
PROTOBUF_NAMESPACE_CLOSE
namespace org {
namespace e2eelab {
namespace skissm {
namespace proto {

// ===================================================================

class get_pre_key_bundle_response_payload final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload) */ {
 public:
  inline get_pre_key_bundle_response_payload() : get_pre_key_bundle_response_payload(nullptr) {}
  ~get_pre_key_bundle_response_payload() override;
  explicit constexpr get_pre_key_bundle_response_payload(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  get_pre_key_bundle_response_payload(const get_pre_key_bundle_response_payload& from);
  get_pre_key_bundle_response_payload(get_pre_key_bundle_response_payload&& from) noexcept
    : get_pre_key_bundle_response_payload() {
    *this = ::std::move(from);
  }

  inline get_pre_key_bundle_response_payload& operator=(const get_pre_key_bundle_response_payload& from) {
    CopyFrom(from);
    return *this;
  }
  inline get_pre_key_bundle_response_payload& operator=(get_pre_key_bundle_response_payload&& from) noexcept {
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
  static const get_pre_key_bundle_response_payload& default_instance() {
    return *internal_default_instance();
  }
  static inline const get_pre_key_bundle_response_payload* internal_default_instance() {
    return reinterpret_cast<const get_pre_key_bundle_response_payload*>(
               &_get_pre_key_bundle_response_payload_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(get_pre_key_bundle_response_payload& a, get_pre_key_bundle_response_payload& b) {
    a.Swap(&b);
  }
  inline void Swap(get_pre_key_bundle_response_payload* other) {
    if (other == this) return;
    if (GetOwningArena() == other->GetOwningArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(get_pre_key_bundle_response_payload* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline get_pre_key_bundle_response_payload* New() const final {
    return new get_pre_key_bundle_response_payload();
  }

  get_pre_key_bundle_response_payload* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<get_pre_key_bundle_response_payload>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const get_pre_key_bundle_response_payload& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom(const get_pre_key_bundle_response_payload& from);
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
  void InternalSwap(get_pre_key_bundle_response_payload* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload";
  }
  protected:
  explicit get_pre_key_bundle_response_payload(::PROTOBUF_NAMESPACE_ID::Arena* arena,
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
    kUserNameFieldNumber = 1,
    kPreKeyBundleFieldNumber = 2,
  };
  // bytes user_name = 1;
  void clear_user_name();
  const std::string& user_name() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_user_name(ArgT0&& arg0, ArgT... args);
  std::string* mutable_user_name();
  PROTOBUF_MUST_USE_RESULT std::string* release_user_name();
  void set_allocated_user_name(std::string* user_name);
  private:
  const std::string& _internal_user_name() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_user_name(const std::string& value);
  std::string* _internal_mutable_user_name();
  public:

  // .org.e2eelab.skissm.proto.e2ee_pre_key_bundle pre_key_bundle = 2;
  bool has_pre_key_bundle() const;
  private:
  bool _internal_has_pre_key_bundle() const;
  public:
  void clear_pre_key_bundle();
  const ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle& pre_key_bundle() const;
  PROTOBUF_MUST_USE_RESULT ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* release_pre_key_bundle();
  ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* mutable_pre_key_bundle();
  void set_allocated_pre_key_bundle(::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* pre_key_bundle);
  private:
  const ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle& _internal_pre_key_bundle() const;
  ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* _internal_mutable_pre_key_bundle();
  public:
  void unsafe_arena_set_allocated_pre_key_bundle(
      ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* pre_key_bundle);
  ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* unsafe_arena_release_pre_key_bundle();

  // @@protoc_insertion_point(class_scope:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr user_name_;
  ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* pre_key_bundle_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// get_pre_key_bundle_response_payload

// bytes user_name = 1;
inline void get_pre_key_bundle_response_payload::clear_user_name() {
  user_name_.ClearToEmpty();
}
inline const std::string& get_pre_key_bundle_response_payload::user_name() const {
  // @@protoc_insertion_point(field_get:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload.user_name)
  return _internal_user_name();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void get_pre_key_bundle_response_payload::set_user_name(ArgT0&& arg0, ArgT... args) {
 
 user_name_.SetBytes(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload.user_name)
}
inline std::string* get_pre_key_bundle_response_payload::mutable_user_name() {
  std::string* _s = _internal_mutable_user_name();
  // @@protoc_insertion_point(field_mutable:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload.user_name)
  return _s;
}
inline const std::string& get_pre_key_bundle_response_payload::_internal_user_name() const {
  return user_name_.Get();
}
inline void get_pre_key_bundle_response_payload::_internal_set_user_name(const std::string& value) {
  
  user_name_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* get_pre_key_bundle_response_payload::_internal_mutable_user_name() {
  
  return user_name_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* get_pre_key_bundle_response_payload::release_user_name() {
  // @@protoc_insertion_point(field_release:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload.user_name)
  return user_name_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void get_pre_key_bundle_response_payload::set_allocated_user_name(std::string* user_name) {
  if (user_name != nullptr) {
    
  } else {
    
  }
  user_name_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), user_name,
      GetArenaForAllocation());
  // @@protoc_insertion_point(field_set_allocated:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload.user_name)
}

// .org.e2eelab.skissm.proto.e2ee_pre_key_bundle pre_key_bundle = 2;
inline bool get_pre_key_bundle_response_payload::_internal_has_pre_key_bundle() const {
  return this != internal_default_instance() && pre_key_bundle_ != nullptr;
}
inline bool get_pre_key_bundle_response_payload::has_pre_key_bundle() const {
  return _internal_has_pre_key_bundle();
}
inline const ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle& get_pre_key_bundle_response_payload::_internal_pre_key_bundle() const {
  const ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* p = pre_key_bundle_;
  return p != nullptr ? *p : reinterpret_cast<const ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle&>(
      ::org::e2eelab::skissm::proto::_e2ee_pre_key_bundle_default_instance_);
}
inline const ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle& get_pre_key_bundle_response_payload::pre_key_bundle() const {
  // @@protoc_insertion_point(field_get:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload.pre_key_bundle)
  return _internal_pre_key_bundle();
}
inline void get_pre_key_bundle_response_payload::unsafe_arena_set_allocated_pre_key_bundle(
    ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* pre_key_bundle) {
  if (GetArenaForAllocation() == nullptr) {
    delete reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(pre_key_bundle_);
  }
  pre_key_bundle_ = pre_key_bundle;
  if (pre_key_bundle) {
    
  } else {
    
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload.pre_key_bundle)
}
inline ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* get_pre_key_bundle_response_payload::release_pre_key_bundle() {
  
  ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* temp = pre_key_bundle_;
  pre_key_bundle_ = nullptr;
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
inline ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* get_pre_key_bundle_response_payload::unsafe_arena_release_pre_key_bundle() {
  // @@protoc_insertion_point(field_release:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload.pre_key_bundle)
  
  ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* temp = pre_key_bundle_;
  pre_key_bundle_ = nullptr;
  return temp;
}
inline ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* get_pre_key_bundle_response_payload::_internal_mutable_pre_key_bundle() {
  
  if (pre_key_bundle_ == nullptr) {
    auto* p = CreateMaybeMessage<::org::e2eelab::skissm::proto::e2ee_pre_key_bundle>(GetArenaForAllocation());
    pre_key_bundle_ = p;
  }
  return pre_key_bundle_;
}
inline ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* get_pre_key_bundle_response_payload::mutable_pre_key_bundle() {
  ::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* _msg = _internal_mutable_pre_key_bundle();
  // @@protoc_insertion_point(field_mutable:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload.pre_key_bundle)
  return _msg;
}
inline void get_pre_key_bundle_response_payload::set_allocated_pre_key_bundle(::org::e2eelab::skissm::proto::e2ee_pre_key_bundle* pre_key_bundle) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  if (message_arena == nullptr) {
    delete reinterpret_cast< ::PROTOBUF_NAMESPACE_ID::MessageLite*>(pre_key_bundle_);
  }
  if (pre_key_bundle) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
        ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper<
            ::PROTOBUF_NAMESPACE_ID::MessageLite>::GetOwningArena(
                reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(pre_key_bundle));
    if (message_arena != submessage_arena) {
      pre_key_bundle = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, pre_key_bundle, submessage_arena);
    }
    
  } else {
    
  }
  pre_key_bundle_ = pre_key_bundle;
  // @@protoc_insertion_point(field_set_allocated:org.e2eelab.skissm.proto.get_pre_key_bundle_response_payload.pre_key_bundle)
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
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_skissm_2fget_5fpre_5fkey_5fbundle_5fresponse_5fpayload_2eproto
