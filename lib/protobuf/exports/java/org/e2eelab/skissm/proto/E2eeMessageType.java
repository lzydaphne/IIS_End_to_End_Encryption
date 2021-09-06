// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: e2ee_message_type.proto

package org.e2eelab.skissm.proto;

public final class E2eeMessageType {
  private E2eeMessageType() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  /**
   * Protobuf enum {@code org.e2eelab.skissm.proto.e2ee_message_type}
   */
  public enum e2ee_message_type
      implements com.google.protobuf.ProtocolMessageEnum {
    /**
     * <code>PRE_KEY = 0;</code>
     */
    PRE_KEY(0),
    /**
     * <code>MESSAGE = 1;</code>
     */
    MESSAGE(1),
    /**
     * <code>GROUP_MESSAGE = 2;</code>
     */
    GROUP_MESSAGE(2),
    UNRECOGNIZED(-1),
    ;

    /**
     * <code>PRE_KEY = 0;</code>
     */
    public static final int PRE_KEY_VALUE = 0;
    /**
     * <code>MESSAGE = 1;</code>
     */
    public static final int MESSAGE_VALUE = 1;
    /**
     * <code>GROUP_MESSAGE = 2;</code>
     */
    public static final int GROUP_MESSAGE_VALUE = 2;


    public final int getNumber() {
      if (this == UNRECOGNIZED) {
        throw new java.lang.IllegalArgumentException(
            "Can't get the number of an unknown enum value.");
      }
      return value;
    }

    /**
     * @param value The numeric wire value of the corresponding enum entry.
     * @return The enum associated with the given numeric wire value.
     * @deprecated Use {@link #forNumber(int)} instead.
     */
    @java.lang.Deprecated
    public static e2ee_message_type valueOf(int value) {
      return forNumber(value);
    }

    /**
     * @param value The numeric wire value of the corresponding enum entry.
     * @return The enum associated with the given numeric wire value.
     */
    public static e2ee_message_type forNumber(int value) {
      switch (value) {
        case 0: return PRE_KEY;
        case 1: return MESSAGE;
        case 2: return GROUP_MESSAGE;
        default: return null;
      }
    }

    public static com.google.protobuf.Internal.EnumLiteMap<e2ee_message_type>
        internalGetValueMap() {
      return internalValueMap;
    }
    private static final com.google.protobuf.Internal.EnumLiteMap<
        e2ee_message_type> internalValueMap =
          new com.google.protobuf.Internal.EnumLiteMap<e2ee_message_type>() {
            public e2ee_message_type findValueByNumber(int number) {
              return e2ee_message_type.forNumber(number);
            }
          };

    public final com.google.protobuf.Descriptors.EnumValueDescriptor
        getValueDescriptor() {
      if (this == UNRECOGNIZED) {
        throw new java.lang.IllegalStateException(
            "Can't get the descriptor of an unrecognized enum value.");
      }
      return getDescriptor().getValues().get(ordinal());
    }
    public final com.google.protobuf.Descriptors.EnumDescriptor
        getDescriptorForType() {
      return getDescriptor();
    }
    public static final com.google.protobuf.Descriptors.EnumDescriptor
        getDescriptor() {
      return org.e2eelab.skissm.proto.E2eeMessageType.getDescriptor().getEnumTypes().get(0);
    }

    private static final e2ee_message_type[] VALUES = values();

    public static e2ee_message_type valueOf(
        com.google.protobuf.Descriptors.EnumValueDescriptor desc) {
      if (desc.getType() != getDescriptor()) {
        throw new java.lang.IllegalArgumentException(
          "EnumValueDescriptor is not for this type.");
      }
      if (desc.getIndex() == -1) {
        return UNRECOGNIZED;
      }
      return VALUES[desc.getIndex()];
    }

    private final int value;

    private e2ee_message_type(int value) {
      this.value = value;
    }

    // @@protoc_insertion_point(enum_scope:org.e2eelab.skissm.proto.e2ee_message_type)
  }


  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\027e2ee_message_type.proto\022\030org.e2eelab.s" +
      "kissm.proto*@\n\021e2ee_message_type\022\013\n\007PRE_" +
      "KEY\020\000\022\013\n\007MESSAGE\020\001\022\021\n\rGROUP_MESSAGE\020\002B+\n" +
      "\030org.e2eelab.skissm.protoB\017E2eeMessageTy" +
      "peb\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
  }

  // @@protoc_insertion_point(outer_class_scope)
}
