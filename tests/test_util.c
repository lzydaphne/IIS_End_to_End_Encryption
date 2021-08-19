typedef int bool;
#define true 1
#define false 0

#include <stdio.h>
#include <string.h>

#include "account.h"

bool is_equal_data(ProtobufCBinaryData *data1, ProtobufCBinaryData *data2)
{
  if (data1->len != data2->len)
  {
    return false;
  }

  for (int i = 0; i < data1->len; i++)
  {
    if (data1->data[i] != data2->data[i])
    {
      return false;
    }
  }

  return true;
}

bool is_equal_str(char *str1, char *str2)
{
  int len1 = strlen(str1);
  int len2 = strlen(str2);

  if (len1 != len2)
  {
    return false;
  }

  for (int i = 0; i < len1; i++)
  {
    if (str1[i] != str2[i])
    {
      return false;
    }
  }

  return true;
}

bool is_equal_address(Org__E2eelab__Lib__Protobuf__E2eeAddress *address1, Org__E2eelab__Lib__Protobuf__E2eeAddress *address2)
{
  if (!is_equal_data(&(address1->user_id), &(address2->user_id)))
  {
    return false;
  }
  if (!is_equal_data(&(address1->domain), &(address2->domain)))
  {
    return false;
  }
  if (!is_equal_data(&(address1->device_id), &(address2->device_id)))
  {
    return false;
  }

  return true;
}

bool is_equal_keypair(Org__E2eelab__Lib__Protobuf__KeyPair *keypair1, Org__E2eelab__Lib__Protobuf__KeyPair *keypair2)
{
  if (!is_equal_data(&(keypair1->public_key), &(keypair2->public_key)))
  {
    return false;
  }
  if (!is_equal_data(&(keypair1->private_key), &(keypair2->private_key)))
  {
    return false;
  }

  return true;
}

bool is_equal_spk(Org__E2eelab__Lib__Protobuf__SignedPreKeyPair *spk1, Org__E2eelab__Lib__Protobuf__SignedPreKeyPair *spk2)
{
  if (spk1->spk_id != spk2->spk_id)
  {
    return false;
  }
  if (!is_equal_keypair(spk1->key_pair, spk2->key_pair))
  {
    return false;
  }
  if (!is_equal_data(&(spk1->signature), &(spk2->signature)))
  {
    return false;
  }
  if (spk1->ttl != spk2->ttl)
  {
    return false;
  }

  return true;
}

bool is_equal_opk(Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair *opk1, Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair *opk2)
{
  if (opk1->opk_id != opk2->opk_id)
  {
    return false;
  }
  if (!is_equal_keypair(opk1->key_pair, opk2->key_pair))
  {

    return false;
  }

  return true;
}

bool is_equal_account(Org__E2eelab__Lib__Protobuf__E2eeAccount *account1, Org__E2eelab__Lib__Protobuf__E2eeAccount *account2)
{
  if (account1->version != account2->version)
  {
    printf("version not match");
    return false;
  }
  if (account1->saved != account2->saved)
  {
    printf("saved not match");
    return false;
  }
  if (!is_equal_address(account1->address, account2->address))
  {
    printf("address not match");
    return false;
  }
  if (!is_equal_keypair(account1->identity_key_pair, account2->identity_key_pair))
  {
    printf("keypair not match");
    return false;
  }
  if (!is_equal_spk(account1->signed_pre_key_pair, account2->signed_pre_key_pair))
  {
    printf("spk not match");
    return false;
  }
  if (account1->n_one_time_pre_keys != account2->n_one_time_pre_keys)
  {
    printf("1: %zu\n", account1->n_one_time_pre_keys);
    printf("2: %zu\n", account2->n_one_time_pre_keys);
    printf("n_one_time_pre_keys not match");
    return false;
  }
  for (int i = 0; i < account1->n_one_time_pre_keys; i++)
  {
    if (!is_equal_opk(account1->one_time_pre_keys[i], account2->one_time_pre_keys[i]))
    {
      printf("1: %u\n", account1->one_time_pre_keys[i]->opk_id);
      printf("2: %u\n", account2->one_time_pre_keys[i]->opk_id);
      printf("%d opk not match\n", i);
      return false;
    }
  }
  if (account1->next_signed_pre_key_id != account2->next_signed_pre_key_id)
  {
    printf("next_signed_pre_key_id not match");
    return false;
  }
  if (account1->next_one_time_pre_key_id != account2->next_one_time_pre_key_id)
  {
    printf("next_one_time_pre_key_id not match");
    return false;
  }

  return true;
}

bool is_equal_session(Org__E2eelab__Lib__Protobuf__E2eeSession *session_1, Org__E2eelab__Lib__Protobuf__E2eeSession *session_2)
{
  if (session_1->version != session_2->version)
  {
    printf("version not match");
    return false;
  }
  if (!is_equal_data(&(session_1->session_id), &(session_2->session_id)))
  {
    printf("session_id not match");
    return false;
  }
  if (!is_equal_address(session_1->from, session_2->from))
  {
    printf("from not match");
    return false;
  }
  if (!is_equal_address(session_1->to, session_2->to))
  {
    printf("to not match");
    return false;
  }
  if (!is_equal_data(&(session_1->alice_identity_key), &(session_2->alice_identity_key)))
  {
    printf("alice_identity_key not match");
    return false;
  }
  if (!is_equal_data(&(session_1->alice_ephemeral_key), &(session_2->alice_ephemeral_key)))
  {
    printf("alice_ephemeral_key not match");
    return false;
  }
  if (!is_equal_data(&(session_1->bob_signed_pre_key), &(session_2->bob_signed_pre_key)))
  {
    printf("bob_signed_pre_key not match");
    return false;
  }
  if (!is_equal_data(&(session_1->bob_one_time_pre_key), &(session_2->bob_one_time_pre_key)))
  {
    printf("bob_one_time_pre_key not match");
    return false;
  }
  if (!is_equal_data(&(session_1->associated_data), &(session_2->associated_data)))
  {
    printf("associated_data not match");
    return false;
  }

  return true;
}

bool is_equal_group_session(Org__E2eelab__Lib__Protobuf__E2eeGroupSession *group_session_1, Org__E2eelab__Lib__Protobuf__E2eeGroupSession *group_session_2)
{
  if (group_session_1->version != group_session_2->version)
  {
    printf("version not match");
    return false;
  }
  if (!is_equal_data(&(group_session_1->session_id), &(group_session_2->session_id)))
  {
    printf("session_id not match");
    return false;
  }
  if (!is_equal_address(group_session_1->session_owner, group_session_2->session_owner))
  {
    printf("session_owner not match");
    return false;
  }
  if (!is_equal_address(group_session_1->group_address, group_session_2->group_address))
  {
    printf("group_address not match");
    return false;
  }
  if (!is_equal_data(&(group_session_1->chain_key), &(group_session_2->chain_key)))
  {
    printf("chain_key not match");
    return false;
  }
  if (!is_equal_data(&(group_session_1->signature_private_key), &(group_session_2->signature_private_key)))
  {
    printf("signature_private_key not match");
    return false;
  }
  if (!is_equal_data(&(group_session_1->signature_public_key), &(group_session_2->signature_public_key)))
  {
    printf("signature_public_key not match");
    return false;
  }
  if (!is_equal_data(&(group_session_1->associated_data), &(group_session_2->associated_data)))
  {
    printf("associated_data not match");
    return false;
  }

  return true;
}

void mock_data(ProtobufCBinaryData *to, const char *from)
{
  size_t from_len = strlen(from);
  to->data = (uint8_t *)malloc(from_len);
  memcpy(to->data, from, from_len);
  to->len = from_len;
}

void mock_string(char **to, const char *from)
{
  size_t from_len = sizeof(from);
  *to = (char *)malloc(from_len);
  memcpy(*to, from, from_len);
}

void mock_address(Org__E2eelab__Lib__Protobuf__E2eeAddress **address, const char *user_id, const char *domain, const char *device_id)
{
  *address = malloc(sizeof(Org__E2eelab__Lib__Protobuf__E2eeAddress));
  org__e2eelab__lib__protobuf__e2ee_address__init((*address));

  mock_data(&((*address)->user_id), user_id);
  mock_data(&((*address)->domain), domain);
  mock_data(&((*address)->device_id), device_id);
}

void mock_keypair(Org__E2eelab__Lib__Protobuf__KeyPair **keypair, const char *public_key, const char *private_key)
{
  *keypair = malloc(sizeof(Org__E2eelab__Lib__Protobuf__KeyPair));
  org__e2eelab__lib__protobuf__key_pair__init(*keypair);

  mock_data(&((*keypair)->public_key), public_key);
  mock_data(&((*keypair)->private_key), private_key);
}

void mock_signed_pre_keypair(Org__E2eelab__Lib__Protobuf__SignedPreKeyPair **signed_pre_keypair, uint32_t spk_id, const char *public_key, const char *private_key, const char *signature)
{
  *signed_pre_keypair = malloc(sizeof(Org__E2eelab__Lib__Protobuf__SignedPreKeyPair));
  org__e2eelab__lib__protobuf__signed_pre_key_pair__init(*signed_pre_keypair);
  mock_data(&((*signed_pre_keypair)->signature), signature);
  mock_keypair(&((*signed_pre_keypair)->key_pair), public_key, private_key);
  (*signed_pre_keypair)->spk_id = spk_id;
}

void mock_onetime_pre_keypiar(Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair **onetime_pre_keypiar, uint32_t opk_id, protobuf_c_boolean used, const char *public_key, const char *private_key)
{
  *onetime_pre_keypiar = malloc(sizeof(Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair));
  org__e2eelab__lib__protobuf__one_time_pre_key_pair__init(*onetime_pre_keypiar);
  mock_keypair(&((*onetime_pre_keypiar)->key_pair), public_key, private_key);
  (*onetime_pre_keypiar)->opk_id = opk_id;
  (*onetime_pre_keypiar)->used = used;
}

void free_account(Org__E2eelab__Lib__Protobuf__E2eeAccount *account)
{
  org__e2eelab__lib__protobuf__e2ee_account__free_unpacked(account, NULL);
}

void free_keypair(Org__E2eelab__Lib__Protobuf__KeyPair *keypair)
{
  org__e2eelab__lib__protobuf__key_pair__free_unpacked(keypair, NULL);
}

void free_signed_pre_keypair(Org__E2eelab__Lib__Protobuf__SignedPreKeyPair *signed_pre_keypair)
{
  org__e2eelab__lib__protobuf__signed_pre_key_pair__free_unpacked(signed_pre_keypair, NULL);
}

void free_onetime_pre_keypiar(Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair *onetime_pre_keypiar)
{
  org__e2eelab__lib__protobuf__one_time_pre_key_pair__free_unpacked(onetime_pre_keypiar, NULL);
}

void free_address(Org__E2eelab__Lib__Protobuf__E2eeAddress *address)
{
  org__e2eelab__lib__protobuf__e2ee_address__free_unpacked(address, NULL);
}