#ifndef TEST_UTIL_H_
#define TEST_UTIL_H_

#include "skissm.h"

// is_equal
bool is_equal_data(ProtobufCBinaryData *data1, ProtobufCBinaryData *data2);
bool is_equal_str(char *str1, char *str2);
bool is_equal_address(Org__E2eelab__Lib__Protobuf__E2eeAddress *address1, Org__E2eelab__Lib__Protobuf__E2eeAddress *address2);
bool is_equal_keypair(Org__E2eelab__Lib__Protobuf__KeyPair *keypair1, Org__E2eelab__Lib__Protobuf__KeyPair *keypair2);
bool is_equal_spk(Org__E2eelab__Lib__Protobuf__SignedPreKeyPair *spk1, Org__E2eelab__Lib__Protobuf__SignedPreKeyPair *spk2);
bool is_equal_opk(Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair *opk1, Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair *opk2);
bool is_equal_account(Org__E2eelab__Lib__Protobuf__E2eeAccount *account1, Org__E2eelab__Lib__Protobuf__E2eeAccount *account2);
bool is_equal_session(Org__E2eelab__Lib__Protobuf__E2eeSession *session_1, Org__E2eelab__Lib__Protobuf__E2eeSession *session_2);
bool is_equal_group_session(Org__E2eelab__Lib__Protobuf__E2eeGroupSession *group_session_1, Org__E2eelab__Lib__Protobuf__E2eeGroupSession *group_session_2);

// mock
void mock_data(ProtobufCBinaryData *to, const char *from);
void mock_string(char **to, const char *from);
void mock_address(Org__E2eelab__Lib__Protobuf__E2eeAddress **address_pp, const char *user_id, const char *domain, const char *device_id);
void mock_keypair(Org__E2eelab__Lib__Protobuf__KeyPair **keypair, const char *public_key, const char *private_key);
void mock_signed_pre_keypair(Org__E2eelab__Lib__Protobuf__SignedPreKeyPair **signed_pre_keypair, uint32_t spk_id, const char *public_key, const char *private_key, const char *signature);
void mock_onetime_pre_keypiar(Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair **onetime_pre_keypiar, uint32_t opk_id, protobuf_c_boolean used, const char *public_key, const char *private_key);

// free
void free_account(Org__E2eelab__Lib__Protobuf__E2eeAccount *account);
void free_keypair(Org__E2eelab__Lib__Protobuf__KeyPair *keypair);
void free_signed_pre_keypair(Org__E2eelab__Lib__Protobuf__SignedPreKeyPair *signed_pre_keypair);
void free_onetime_pre_keypiar(Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair *onetime_pre_keypiar);
void free_address(Org__E2eelab__Lib__Protobuf__E2eeAddress *address);

#endif /* TEST_UTIL_H_ */