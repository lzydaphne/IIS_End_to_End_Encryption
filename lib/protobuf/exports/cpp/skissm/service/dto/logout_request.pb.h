// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/service/dto/logout_request.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_skissm_2fservice_2fdto_2flogout_5frequest_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_skissm_2fservice_2fdto_2flogout_5frequest_2eproto

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
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_skissm_2fservice_2fdto_2flogout_5frequest_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_skissm_2fservice_2fdto_2flogout_5frequest_2eproto {
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
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fservice_2fdto_2flogout_5frequest_2eproto;
namespace org {
namespace e2eelab {
namespace server {
namespace grpc {
namespace auth {
class logout_request;
struct logout_requestDefaultTypeInternal;
extern logout_requestDefaultTypeInternal _logout_request_default_instance_;
}  // namespace auth
}  // namespace grpc
}  // namespace server
}  // namespace e2eelab
}  // namespace org
PROTOBUF_NAMESPACE_OPEN
template<> ::org::e2eelab::server::grpc::auth::logout_request* Arena::CreateMaybeMessage<::org::e2eelab::server::grpc::auth::logout_request>(Arena*);
PROTOBUF_NAMESPACE_CLOSE
namespace org {
namespace e2eelab {
namespace server {
namespace grpc {
namespace auth {

// ===================================================================

class logout_request final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:org.e2eelab.server.grpc.auth.logout_request) */ {
 public:
  inline logout_request() : logout_request(nullptr) {}
  ~logout_request() override;
  explicit constexpr logout_request(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  logout_request(const logout_request& from);
  logout_request(logout_request&& from) noexcept
    : logout_request() {
    *this = ::std::move(from);
  }

  inline logout_request& operator=(const logout_request& from) {
    CopyFrom(from);
    return *this;
  }
  inline logout_request& operator=(logout_request&& from) noexcept {
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
  static const logout_request& default_instance() {
    return *internal_default_instance();
  }
  static inline const logout_request* internal_default_instance() {
    return reinterpret_cast<const logout_request*>(
               &_logout_request_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(logout_request& a, logout_request& b) {
    a.Swap(&b);
  }
  inline void Swap(logout_request* other) {
    if (other == this) return;
    if (GetOwningArena() == other->GetOwningArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(logout_request* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline logout_request* New() const final {
    return new logout_request();
  }

  logout_request* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<logout_request>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const logout_request& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom(const logout_request& from);
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
  void InternalSwap(logout_request* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "org.e2eelab.server.grpc.auth.logout_request";
  }
  protected:
  explicit logout_request(::PROTOBUF_NAMESPACE_ID::Arena* arena,
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
    kUserIdFieldNumber = 1,
  };
  // string userId = 1;
  void clear_userid();
  const std::string& userid() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_userid(ArgT0&& arg0, ArgT... args);
  std::string* mutable_userid();
  PROTOBUF_MUST_USE_RESULT std::string* release_userid();
  void set_allocated_userid(std::string* userid);
  private:
  const std::string& _internal_userid() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_userid(const std::string& value);
  std::string* _internal_mutable_userid();
  public:

  // @@protoc_insertion_point(class_scope:org.e2eelab.server.grpc.auth.logout_request)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr userid_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_skissm_2fservice_2fdto_2flogout_5frequest_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// logout_request

// string userId = 1;
inline void logout_request::clear_userid() {
  userid_.ClearToEmpty();
}
inline const std::string& logout_request::userid() const {
  // @@protoc_insertion_point(field_get:org.e2eelab.server.grpc.auth.logout_request.userId)
  return _internal_userid();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void logout_request::set_userid(ArgT0&& arg0, ArgT... args) {
 
 userid_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:org.e2eelab.server.grpc.auth.logout_request.userId)
}
inline std::string* logout_request::mutable_userid() {
  std::string* _s = _internal_mutable_userid();
  // @@protoc_insertion_point(field_mutable:org.e2eelab.server.grpc.auth.logout_request.userId)
  return _s;
}
inline const std::string& logout_request::_internal_userid() const {
  return userid_.Get();
}
inline void logout_request::_internal_set_userid(const std::string& value) {
  
  userid_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* logout_request::_internal_mutable_userid() {
  
  return userid_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* logout_request::release_userid() {
  // @@protoc_insertion_point(field_release:org.e2eelab.server.grpc.auth.logout_request.userId)
  return userid_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void logout_request::set_allocated_userid(std::string* userid) {
  if (userid != nullptr) {
    
  } else {
    
  }
  userid_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), userid,
      GetArenaForAllocation());
  // @@protoc_insertion_point(field_set_allocated:org.e2eelab.server.grpc.auth.logout_request.userId)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__

// @@protoc_insertion_point(namespace_scope)

}  // namespace auth
}  // namespace grpc
}  // namespace server
}  // namespace e2eelab
}  // namespace org

// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_skissm_2fservice_2fdto_2flogout_5frequest_2eproto
