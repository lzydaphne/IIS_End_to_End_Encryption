// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/receiver_chain_node.proto

#include "skissm/receiver_chain_node.pb.h"

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
constexpr receiver_chain_node::receiver_chain_node(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : ratchet_key_public_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string)
  , chain_key_(nullptr){}
struct receiver_chain_nodeDefaultTypeInternal {
  constexpr receiver_chain_nodeDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~receiver_chain_nodeDefaultTypeInternal() {}
  union {
    receiver_chain_node _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT receiver_chain_nodeDefaultTypeInternal _receiver_chain_node_default_instance_;
}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org
static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_skissm_2freceiver_5fchain_5fnode_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_skissm_2freceiver_5fchain_5fnode_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_skissm_2freceiver_5fchain_5fnode_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_skissm_2freceiver_5fchain_5fnode_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::receiver_chain_node, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::receiver_chain_node, ratchet_key_public_),
  PROTOBUF_FIELD_OFFSET(::org::e2eelab::skissm::proto::receiver_chain_node, chain_key_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::org::e2eelab::skissm::proto::receiver_chain_node)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::org::e2eelab::skissm::proto::_receiver_chain_node_default_instance_),
};

const char descriptor_table_protodef_skissm_2freceiver_5fchain_5fnode_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n skissm/receiver_chain_node.proto\022\030org."
  "e2eelab.skissm.proto\032\026skissm/chain_key.p"
  "roto\"i\n\023receiver_chain_node\022\032\n\022ratchet_k"
  "ey_public\030\001 \001(\014\0226\n\tchain_key\030\002 \001(\0132#.org"
  ".e2eelab.skissm.proto.chain_keyB\023B\021Recei"
  "verChainNodeb\006proto3"
  ;
static const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable*const descriptor_table_skissm_2freceiver_5fchain_5fnode_2eproto_deps[1] = {
  &::descriptor_table_skissm_2fchain_5fkey_2eproto,
};
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_skissm_2freceiver_5fchain_5fnode_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2freceiver_5fchain_5fnode_2eproto = {
  false, false, 220, descriptor_table_protodef_skissm_2freceiver_5fchain_5fnode_2eproto, "skissm/receiver_chain_node.proto", 
  &descriptor_table_skissm_2freceiver_5fchain_5fnode_2eproto_once, descriptor_table_skissm_2freceiver_5fchain_5fnode_2eproto_deps, 1, 1,
  schemas, file_default_instances, TableStruct_skissm_2freceiver_5fchain_5fnode_2eproto::offsets,
  file_level_metadata_skissm_2freceiver_5fchain_5fnode_2eproto, file_level_enum_descriptors_skissm_2freceiver_5fchain_5fnode_2eproto, file_level_service_descriptors_skissm_2freceiver_5fchain_5fnode_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable* descriptor_table_skissm_2freceiver_5fchain_5fnode_2eproto_getter() {
  return &descriptor_table_skissm_2freceiver_5fchain_5fnode_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY static ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptorsRunner dynamic_init_dummy_skissm_2freceiver_5fchain_5fnode_2eproto(&descriptor_table_skissm_2freceiver_5fchain_5fnode_2eproto);
namespace org {
namespace e2eelab {
namespace skissm {
namespace proto {

// ===================================================================

class receiver_chain_node::_Internal {
 public:
  static const ::org::e2eelab::skissm::proto::chain_key& chain_key(const receiver_chain_node* msg);
};

const ::org::e2eelab::skissm::proto::chain_key&
receiver_chain_node::_Internal::chain_key(const receiver_chain_node* msg) {
  return *msg->chain_key_;
}
void receiver_chain_node::clear_chain_key() {
  if (GetArenaForAllocation() == nullptr && chain_key_ != nullptr) {
    delete chain_key_;
  }
  chain_key_ = nullptr;
}
receiver_chain_node::receiver_chain_node(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:org.e2eelab.skissm.proto.receiver_chain_node)
}
receiver_chain_node::receiver_chain_node(const receiver_chain_node& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  ratchet_key_public_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (!from._internal_ratchet_key_public().empty()) {
    ratchet_key_public_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_ratchet_key_public(), 
      GetArenaForAllocation());
  }
  if (from._internal_has_chain_key()) {
    chain_key_ = new ::org::e2eelab::skissm::proto::chain_key(*from.chain_key_);
  } else {
    chain_key_ = nullptr;
  }
  // @@protoc_insertion_point(copy_constructor:org.e2eelab.skissm.proto.receiver_chain_node)
}

inline void receiver_chain_node::SharedCtor() {
ratchet_key_public_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
chain_key_ = nullptr;
}

receiver_chain_node::~receiver_chain_node() {
  // @@protoc_insertion_point(destructor:org.e2eelab.skissm.proto.receiver_chain_node)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

inline void receiver_chain_node::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  ratchet_key_public_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (this != internal_default_instance()) delete chain_key_;
}

void receiver_chain_node::ArenaDtor(void* object) {
  receiver_chain_node* _this = reinterpret_cast< receiver_chain_node* >(object);
  (void)_this;
}
void receiver_chain_node::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void receiver_chain_node::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void receiver_chain_node::Clear() {
// @@protoc_insertion_point(message_clear_start:org.e2eelab.skissm.proto.receiver_chain_node)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  ratchet_key_public_.ClearToEmpty();
  if (GetArenaForAllocation() == nullptr && chain_key_ != nullptr) {
    delete chain_key_;
  }
  chain_key_ = nullptr;
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* receiver_chain_node::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // bytes ratchet_key_public = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          auto str = _internal_mutable_ratchet_key_public();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // .org.e2eelab.skissm.proto.chain_key chain_key = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 18)) {
          ptr = ctx->ParseMessage(_internal_mutable_chain_key(), ptr);
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

::PROTOBUF_NAMESPACE_ID::uint8* receiver_chain_node::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:org.e2eelab.skissm.proto.receiver_chain_node)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // bytes ratchet_key_public = 1;
  if (!this->_internal_ratchet_key_public().empty()) {
    target = stream->WriteBytesMaybeAliased(
        1, this->_internal_ratchet_key_public(), target);
  }

  // .org.e2eelab.skissm.proto.chain_key chain_key = 2;
  if (this->_internal_has_chain_key()) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(
        2, _Internal::chain_key(this), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:org.e2eelab.skissm.proto.receiver_chain_node)
  return target;
}

size_t receiver_chain_node::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:org.e2eelab.skissm.proto.receiver_chain_node)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // bytes ratchet_key_public = 1;
  if (!this->_internal_ratchet_key_public().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_ratchet_key_public());
  }

  // .org.e2eelab.skissm.proto.chain_key chain_key = 2;
  if (this->_internal_has_chain_key()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *chain_key_);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData receiver_chain_node::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSizeCheck,
    receiver_chain_node::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*receiver_chain_node::GetClassData() const { return &_class_data_; }

void receiver_chain_node::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message*to,
                      const ::PROTOBUF_NAMESPACE_ID::Message&from) {
  static_cast<receiver_chain_node *>(to)->MergeFrom(
      static_cast<const receiver_chain_node &>(from));
}


void receiver_chain_node::MergeFrom(const receiver_chain_node& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:org.e2eelab.skissm.proto.receiver_chain_node)
  GOOGLE_DCHECK_NE(&from, this);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_ratchet_key_public().empty()) {
    _internal_set_ratchet_key_public(from._internal_ratchet_key_public());
  }
  if (from._internal_has_chain_key()) {
    _internal_mutable_chain_key()->::org::e2eelab::skissm::proto::chain_key::MergeFrom(from._internal_chain_key());
  }
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void receiver_chain_node::CopyFrom(const receiver_chain_node& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:org.e2eelab.skissm.proto.receiver_chain_node)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool receiver_chain_node::IsInitialized() const {
  return true;
}

void receiver_chain_node::InternalSwap(receiver_chain_node* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &ratchet_key_public_, GetArenaForAllocation(),
      &other->ratchet_key_public_, other->GetArenaForAllocation()
  );
  swap(chain_key_, other->chain_key_);
}

::PROTOBUF_NAMESPACE_ID::Metadata receiver_chain_node::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_skissm_2freceiver_5fchain_5fnode_2eproto_getter, &descriptor_table_skissm_2freceiver_5fchain_5fnode_2eproto_once,
      file_level_metadata_skissm_2freceiver_5fchain_5fnode_2eproto[0]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace proto
}  // namespace skissm
}  // namespace e2eelab
}  // namespace org
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::org::e2eelab::skissm::proto::receiver_chain_node* Arena::CreateMaybeMessage< ::org::e2eelab::skissm::proto::receiver_chain_node >(Arena* arena) {
  return Arena::CreateMessageInternal< ::org::e2eelab::skissm::proto::receiver_chain_node >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
