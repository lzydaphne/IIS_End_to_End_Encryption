// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: sender_chain_node.proto

package org.e2eelab.skissm.proto;

public final class SenderChainNode {
  private SenderChainNode() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface sender_chain_nodeOrBuilder extends
      // @@protoc_insertion_point(interface_extends:org.e2eelab.skissm.proto.sender_chain_node)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
     * @return Whether the ratchetKeyPair field is set.
     */
    boolean hasRatchetKeyPair();
    /**
     * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
     * @return The ratchetKeyPair.
     */
    org.e2eelab.skissm.proto.KeyPair.key_pair getRatchetKeyPair();
    /**
     * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
     */
    org.e2eelab.skissm.proto.KeyPair.key_pairOrBuilder getRatchetKeyPairOrBuilder();

    /**
     * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
     * @return Whether the chainKey field is set.
     */
    boolean hasChainKey();
    /**
     * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
     * @return The chainKey.
     */
    org.e2eelab.skissm.proto.ChainKey.chain_key getChainKey();
    /**
     * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
     */
    org.e2eelab.skissm.proto.ChainKey.chain_keyOrBuilder getChainKeyOrBuilder();
  }
  /**
   * Protobuf type {@code org.e2eelab.skissm.proto.sender_chain_node}
   */
  public static final class sender_chain_node extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:org.e2eelab.skissm.proto.sender_chain_node)
      sender_chain_nodeOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use sender_chain_node.newBuilder() to construct.
    private sender_chain_node(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private sender_chain_node() {
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new sender_chain_node();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private sender_chain_node(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      this();
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
      com.google.protobuf.UnknownFieldSet.Builder unknownFields =
          com.google.protobuf.UnknownFieldSet.newBuilder();
      try {
        boolean done = false;
        while (!done) {
          int tag = input.readTag();
          switch (tag) {
            case 0:
              done = true;
              break;
            case 10: {
              org.e2eelab.skissm.proto.KeyPair.key_pair.Builder subBuilder = null;
              if (ratchetKeyPair_ != null) {
                subBuilder = ratchetKeyPair_.toBuilder();
              }
              ratchetKeyPair_ = input.readMessage(org.e2eelab.skissm.proto.KeyPair.key_pair.parser(), extensionRegistry);
              if (subBuilder != null) {
                subBuilder.mergeFrom(ratchetKeyPair_);
                ratchetKeyPair_ = subBuilder.buildPartial();
              }

              break;
            }
            case 18: {
              org.e2eelab.skissm.proto.ChainKey.chain_key.Builder subBuilder = null;
              if (chainKey_ != null) {
                subBuilder = chainKey_.toBuilder();
              }
              chainKey_ = input.readMessage(org.e2eelab.skissm.proto.ChainKey.chain_key.parser(), extensionRegistry);
              if (subBuilder != null) {
                subBuilder.mergeFrom(chainKey_);
                chainKey_ = subBuilder.buildPartial();
              }

              break;
            }
            default: {
              if (!parseUnknownField(
                  input, unknownFields, extensionRegistry, tag)) {
                done = true;
              }
              break;
            }
          }
        }
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        throw e.setUnfinishedMessage(this);
      } catch (java.io.IOException e) {
        throw new com.google.protobuf.InvalidProtocolBufferException(
            e).setUnfinishedMessage(this);
      } finally {
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return org.e2eelab.skissm.proto.SenderChainNode.internal_static_org_e2eelab_skissm_proto_sender_chain_node_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return org.e2eelab.skissm.proto.SenderChainNode.internal_static_org_e2eelab_skissm_proto_sender_chain_node_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node.class, org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node.Builder.class);
    }

    public static final int RATCHET_KEY_PAIR_FIELD_NUMBER = 1;
    private org.e2eelab.skissm.proto.KeyPair.key_pair ratchetKeyPair_;
    /**
     * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
     * @return Whether the ratchetKeyPair field is set.
     */
    @java.lang.Override
    public boolean hasRatchetKeyPair() {
      return ratchetKeyPair_ != null;
    }
    /**
     * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
     * @return The ratchetKeyPair.
     */
    @java.lang.Override
    public org.e2eelab.skissm.proto.KeyPair.key_pair getRatchetKeyPair() {
      return ratchetKeyPair_ == null ? org.e2eelab.skissm.proto.KeyPair.key_pair.getDefaultInstance() : ratchetKeyPair_;
    }
    /**
     * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
     */
    @java.lang.Override
    public org.e2eelab.skissm.proto.KeyPair.key_pairOrBuilder getRatchetKeyPairOrBuilder() {
      return getRatchetKeyPair();
    }

    public static final int CHAIN_KEY_FIELD_NUMBER = 2;
    private org.e2eelab.skissm.proto.ChainKey.chain_key chainKey_;
    /**
     * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
     * @return Whether the chainKey field is set.
     */
    @java.lang.Override
    public boolean hasChainKey() {
      return chainKey_ != null;
    }
    /**
     * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
     * @return The chainKey.
     */
    @java.lang.Override
    public org.e2eelab.skissm.proto.ChainKey.chain_key getChainKey() {
      return chainKey_ == null ? org.e2eelab.skissm.proto.ChainKey.chain_key.getDefaultInstance() : chainKey_;
    }
    /**
     * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
     */
    @java.lang.Override
    public org.e2eelab.skissm.proto.ChainKey.chain_keyOrBuilder getChainKeyOrBuilder() {
      return getChainKey();
    }

    private byte memoizedIsInitialized = -1;
    @java.lang.Override
    public final boolean isInitialized() {
      byte isInitialized = memoizedIsInitialized;
      if (isInitialized == 1) return true;
      if (isInitialized == 0) return false;

      memoizedIsInitialized = 1;
      return true;
    }

    @java.lang.Override
    public void writeTo(com.google.protobuf.CodedOutputStream output)
                        throws java.io.IOException {
      if (ratchetKeyPair_ != null) {
        output.writeMessage(1, getRatchetKeyPair());
      }
      if (chainKey_ != null) {
        output.writeMessage(2, getChainKey());
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (ratchetKeyPair_ != null) {
        size += com.google.protobuf.CodedOutputStream
          .computeMessageSize(1, getRatchetKeyPair());
      }
      if (chainKey_ != null) {
        size += com.google.protobuf.CodedOutputStream
          .computeMessageSize(2, getChainKey());
      }
      size += unknownFields.getSerializedSize();
      memoizedSize = size;
      return size;
    }

    @java.lang.Override
    public boolean equals(final java.lang.Object obj) {
      if (obj == this) {
       return true;
      }
      if (!(obj instanceof org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node)) {
        return super.equals(obj);
      }
      org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node other = (org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node) obj;

      if (hasRatchetKeyPair() != other.hasRatchetKeyPair()) return false;
      if (hasRatchetKeyPair()) {
        if (!getRatchetKeyPair()
            .equals(other.getRatchetKeyPair())) return false;
      }
      if (hasChainKey() != other.hasChainKey()) return false;
      if (hasChainKey()) {
        if (!getChainKey()
            .equals(other.getChainKey())) return false;
      }
      if (!unknownFields.equals(other.unknownFields)) return false;
      return true;
    }

    @java.lang.Override
    public int hashCode() {
      if (memoizedHashCode != 0) {
        return memoizedHashCode;
      }
      int hash = 41;
      hash = (19 * hash) + getDescriptor().hashCode();
      if (hasRatchetKeyPair()) {
        hash = (37 * hash) + RATCHET_KEY_PAIR_FIELD_NUMBER;
        hash = (53 * hash) + getRatchetKeyPair().hashCode();
      }
      if (hasChainKey()) {
        hash = (37 * hash) + CHAIN_KEY_FIELD_NUMBER;
        hash = (53 * hash) + getChainKey().hashCode();
      }
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parseFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }

    @java.lang.Override
    public Builder newBuilderForType() { return newBuilder(); }
    public static Builder newBuilder() {
      return DEFAULT_INSTANCE.toBuilder();
    }
    public static Builder newBuilder(org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node prototype) {
      return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
    }
    @java.lang.Override
    public Builder toBuilder() {
      return this == DEFAULT_INSTANCE
          ? new Builder() : new Builder().mergeFrom(this);
    }

    @java.lang.Override
    protected Builder newBuilderForType(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      Builder builder = new Builder(parent);
      return builder;
    }
    /**
     * Protobuf type {@code org.e2eelab.skissm.proto.sender_chain_node}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:org.e2eelab.skissm.proto.sender_chain_node)
        org.e2eelab.skissm.proto.SenderChainNode.sender_chain_nodeOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return org.e2eelab.skissm.proto.SenderChainNode.internal_static_org_e2eelab_skissm_proto_sender_chain_node_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return org.e2eelab.skissm.proto.SenderChainNode.internal_static_org_e2eelab_skissm_proto_sender_chain_node_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node.class, org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node.Builder.class);
      }

      // Construct using org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node.newBuilder()
      private Builder() {
        maybeForceBuilderInitialization();
      }

      private Builder(
          com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
        super(parent);
        maybeForceBuilderInitialization();
      }
      private void maybeForceBuilderInitialization() {
        if (com.google.protobuf.GeneratedMessageV3
                .alwaysUseFieldBuilders) {
        }
      }
      @java.lang.Override
      public Builder clear() {
        super.clear();
        if (ratchetKeyPairBuilder_ == null) {
          ratchetKeyPair_ = null;
        } else {
          ratchetKeyPair_ = null;
          ratchetKeyPairBuilder_ = null;
        }
        if (chainKeyBuilder_ == null) {
          chainKey_ = null;
        } else {
          chainKey_ = null;
          chainKeyBuilder_ = null;
        }
        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return org.e2eelab.skissm.proto.SenderChainNode.internal_static_org_e2eelab_skissm_proto_sender_chain_node_descriptor;
      }

      @java.lang.Override
      public org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node getDefaultInstanceForType() {
        return org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node.getDefaultInstance();
      }

      @java.lang.Override
      public org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node build() {
        org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node buildPartial() {
        org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node result = new org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node(this);
        if (ratchetKeyPairBuilder_ == null) {
          result.ratchetKeyPair_ = ratchetKeyPair_;
        } else {
          result.ratchetKeyPair_ = ratchetKeyPairBuilder_.build();
        }
        if (chainKeyBuilder_ == null) {
          result.chainKey_ = chainKey_;
        } else {
          result.chainKey_ = chainKeyBuilder_.build();
        }
        onBuilt();
        return result;
      }

      @java.lang.Override
      public Builder clone() {
        return super.clone();
      }
      @java.lang.Override
      public Builder setField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return super.setField(field, value);
      }
      @java.lang.Override
      public Builder clearField(
          com.google.protobuf.Descriptors.FieldDescriptor field) {
        return super.clearField(field);
      }
      @java.lang.Override
      public Builder clearOneof(
          com.google.protobuf.Descriptors.OneofDescriptor oneof) {
        return super.clearOneof(oneof);
      }
      @java.lang.Override
      public Builder setRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          int index, java.lang.Object value) {
        return super.setRepeatedField(field, index, value);
      }
      @java.lang.Override
      public Builder addRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return super.addRepeatedField(field, value);
      }
      @java.lang.Override
      public Builder mergeFrom(com.google.protobuf.Message other) {
        if (other instanceof org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node) {
          return mergeFrom((org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node other) {
        if (other == org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node.getDefaultInstance()) return this;
        if (other.hasRatchetKeyPair()) {
          mergeRatchetKeyPair(other.getRatchetKeyPair());
        }
        if (other.hasChainKey()) {
          mergeChainKey(other.getChainKey());
        }
        this.mergeUnknownFields(other.unknownFields);
        onChanged();
        return this;
      }

      @java.lang.Override
      public final boolean isInitialized() {
        return true;
      }

      @java.lang.Override
      public Builder mergeFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws java.io.IOException {
        org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }

      private org.e2eelab.skissm.proto.KeyPair.key_pair ratchetKeyPair_;
      private com.google.protobuf.SingleFieldBuilderV3<
          org.e2eelab.skissm.proto.KeyPair.key_pair, org.e2eelab.skissm.proto.KeyPair.key_pair.Builder, org.e2eelab.skissm.proto.KeyPair.key_pairOrBuilder> ratchetKeyPairBuilder_;
      /**
       * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
       * @return Whether the ratchetKeyPair field is set.
       */
      public boolean hasRatchetKeyPair() {
        return ratchetKeyPairBuilder_ != null || ratchetKeyPair_ != null;
      }
      /**
       * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
       * @return The ratchetKeyPair.
       */
      public org.e2eelab.skissm.proto.KeyPair.key_pair getRatchetKeyPair() {
        if (ratchetKeyPairBuilder_ == null) {
          return ratchetKeyPair_ == null ? org.e2eelab.skissm.proto.KeyPair.key_pair.getDefaultInstance() : ratchetKeyPair_;
        } else {
          return ratchetKeyPairBuilder_.getMessage();
        }
      }
      /**
       * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
       */
      public Builder setRatchetKeyPair(org.e2eelab.skissm.proto.KeyPair.key_pair value) {
        if (ratchetKeyPairBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          ratchetKeyPair_ = value;
          onChanged();
        } else {
          ratchetKeyPairBuilder_.setMessage(value);
        }

        return this;
      }
      /**
       * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
       */
      public Builder setRatchetKeyPair(
          org.e2eelab.skissm.proto.KeyPair.key_pair.Builder builderForValue) {
        if (ratchetKeyPairBuilder_ == null) {
          ratchetKeyPair_ = builderForValue.build();
          onChanged();
        } else {
          ratchetKeyPairBuilder_.setMessage(builderForValue.build());
        }

        return this;
      }
      /**
       * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
       */
      public Builder mergeRatchetKeyPair(org.e2eelab.skissm.proto.KeyPair.key_pair value) {
        if (ratchetKeyPairBuilder_ == null) {
          if (ratchetKeyPair_ != null) {
            ratchetKeyPair_ =
              org.e2eelab.skissm.proto.KeyPair.key_pair.newBuilder(ratchetKeyPair_).mergeFrom(value).buildPartial();
          } else {
            ratchetKeyPair_ = value;
          }
          onChanged();
        } else {
          ratchetKeyPairBuilder_.mergeFrom(value);
        }

        return this;
      }
      /**
       * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
       */
      public Builder clearRatchetKeyPair() {
        if (ratchetKeyPairBuilder_ == null) {
          ratchetKeyPair_ = null;
          onChanged();
        } else {
          ratchetKeyPair_ = null;
          ratchetKeyPairBuilder_ = null;
        }

        return this;
      }
      /**
       * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
       */
      public org.e2eelab.skissm.proto.KeyPair.key_pair.Builder getRatchetKeyPairBuilder() {
        
        onChanged();
        return getRatchetKeyPairFieldBuilder().getBuilder();
      }
      /**
       * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
       */
      public org.e2eelab.skissm.proto.KeyPair.key_pairOrBuilder getRatchetKeyPairOrBuilder() {
        if (ratchetKeyPairBuilder_ != null) {
          return ratchetKeyPairBuilder_.getMessageOrBuilder();
        } else {
          return ratchetKeyPair_ == null ?
              org.e2eelab.skissm.proto.KeyPair.key_pair.getDefaultInstance() : ratchetKeyPair_;
        }
      }
      /**
       * <code>.org.e2eelab.skissm.proto.key_pair ratchet_key_pair = 1;</code>
       */
      private com.google.protobuf.SingleFieldBuilderV3<
          org.e2eelab.skissm.proto.KeyPair.key_pair, org.e2eelab.skissm.proto.KeyPair.key_pair.Builder, org.e2eelab.skissm.proto.KeyPair.key_pairOrBuilder> 
          getRatchetKeyPairFieldBuilder() {
        if (ratchetKeyPairBuilder_ == null) {
          ratchetKeyPairBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
              org.e2eelab.skissm.proto.KeyPair.key_pair, org.e2eelab.skissm.proto.KeyPair.key_pair.Builder, org.e2eelab.skissm.proto.KeyPair.key_pairOrBuilder>(
                  getRatchetKeyPair(),
                  getParentForChildren(),
                  isClean());
          ratchetKeyPair_ = null;
        }
        return ratchetKeyPairBuilder_;
      }

      private org.e2eelab.skissm.proto.ChainKey.chain_key chainKey_;
      private com.google.protobuf.SingleFieldBuilderV3<
          org.e2eelab.skissm.proto.ChainKey.chain_key, org.e2eelab.skissm.proto.ChainKey.chain_key.Builder, org.e2eelab.skissm.proto.ChainKey.chain_keyOrBuilder> chainKeyBuilder_;
      /**
       * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
       * @return Whether the chainKey field is set.
       */
      public boolean hasChainKey() {
        return chainKeyBuilder_ != null || chainKey_ != null;
      }
      /**
       * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
       * @return The chainKey.
       */
      public org.e2eelab.skissm.proto.ChainKey.chain_key getChainKey() {
        if (chainKeyBuilder_ == null) {
          return chainKey_ == null ? org.e2eelab.skissm.proto.ChainKey.chain_key.getDefaultInstance() : chainKey_;
        } else {
          return chainKeyBuilder_.getMessage();
        }
      }
      /**
       * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
       */
      public Builder setChainKey(org.e2eelab.skissm.proto.ChainKey.chain_key value) {
        if (chainKeyBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          chainKey_ = value;
          onChanged();
        } else {
          chainKeyBuilder_.setMessage(value);
        }

        return this;
      }
      /**
       * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
       */
      public Builder setChainKey(
          org.e2eelab.skissm.proto.ChainKey.chain_key.Builder builderForValue) {
        if (chainKeyBuilder_ == null) {
          chainKey_ = builderForValue.build();
          onChanged();
        } else {
          chainKeyBuilder_.setMessage(builderForValue.build());
        }

        return this;
      }
      /**
       * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
       */
      public Builder mergeChainKey(org.e2eelab.skissm.proto.ChainKey.chain_key value) {
        if (chainKeyBuilder_ == null) {
          if (chainKey_ != null) {
            chainKey_ =
              org.e2eelab.skissm.proto.ChainKey.chain_key.newBuilder(chainKey_).mergeFrom(value).buildPartial();
          } else {
            chainKey_ = value;
          }
          onChanged();
        } else {
          chainKeyBuilder_.mergeFrom(value);
        }

        return this;
      }
      /**
       * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
       */
      public Builder clearChainKey() {
        if (chainKeyBuilder_ == null) {
          chainKey_ = null;
          onChanged();
        } else {
          chainKey_ = null;
          chainKeyBuilder_ = null;
        }

        return this;
      }
      /**
       * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
       */
      public org.e2eelab.skissm.proto.ChainKey.chain_key.Builder getChainKeyBuilder() {
        
        onChanged();
        return getChainKeyFieldBuilder().getBuilder();
      }
      /**
       * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
       */
      public org.e2eelab.skissm.proto.ChainKey.chain_keyOrBuilder getChainKeyOrBuilder() {
        if (chainKeyBuilder_ != null) {
          return chainKeyBuilder_.getMessageOrBuilder();
        } else {
          return chainKey_ == null ?
              org.e2eelab.skissm.proto.ChainKey.chain_key.getDefaultInstance() : chainKey_;
        }
      }
      /**
       * <code>.org.e2eelab.skissm.proto.chain_key chain_key = 2;</code>
       */
      private com.google.protobuf.SingleFieldBuilderV3<
          org.e2eelab.skissm.proto.ChainKey.chain_key, org.e2eelab.skissm.proto.ChainKey.chain_key.Builder, org.e2eelab.skissm.proto.ChainKey.chain_keyOrBuilder> 
          getChainKeyFieldBuilder() {
        if (chainKeyBuilder_ == null) {
          chainKeyBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
              org.e2eelab.skissm.proto.ChainKey.chain_key, org.e2eelab.skissm.proto.ChainKey.chain_key.Builder, org.e2eelab.skissm.proto.ChainKey.chain_keyOrBuilder>(
                  getChainKey(),
                  getParentForChildren(),
                  isClean());
          chainKey_ = null;
        }
        return chainKeyBuilder_;
      }
      @java.lang.Override
      public final Builder setUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.setUnknownFields(unknownFields);
      }

      @java.lang.Override
      public final Builder mergeUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.mergeUnknownFields(unknownFields);
      }


      // @@protoc_insertion_point(builder_scope:org.e2eelab.skissm.proto.sender_chain_node)
    }

    // @@protoc_insertion_point(class_scope:org.e2eelab.skissm.proto.sender_chain_node)
    private static final org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node();
    }

    public static org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<sender_chain_node>
        PARSER = new com.google.protobuf.AbstractParser<sender_chain_node>() {
      @java.lang.Override
      public sender_chain_node parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new sender_chain_node(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<sender_chain_node> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<sender_chain_node> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public org.e2eelab.skissm.proto.SenderChainNode.sender_chain_node getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_org_e2eelab_skissm_proto_sender_chain_node_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_org_e2eelab_skissm_proto_sender_chain_node_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\027sender_chain_node.proto\022\030org.e2eelab.s" +
      "kissm.proto\032\016key_pair.proto\032\017chain_key.p" +
      "roto\"\211\001\n\021sender_chain_node\022<\n\020ratchet_ke" +
      "y_pair\030\001 \001(\0132\".org.e2eelab.skissm.proto." +
      "key_pair\0226\n\tchain_key\030\002 \001(\0132#.org.e2eela" +
      "b.skissm.proto.chain_keyB+\n\030org.e2eelab." +
      "skissm.protoB\017SenderChainNodeb\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          org.e2eelab.skissm.proto.KeyPair.getDescriptor(),
          org.e2eelab.skissm.proto.ChainKey.getDescriptor(),
        });
    internal_static_org_e2eelab_skissm_proto_sender_chain_node_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_org_e2eelab_skissm_proto_sender_chain_node_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_org_e2eelab_skissm_proto_sender_chain_node_descriptor,
        new java.lang.String[] { "RatchetKeyPair", "ChainKey", });
    org.e2eelab.skissm.proto.KeyPair.getDescriptor();
    org.e2eelab.skissm.proto.ChainKey.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
