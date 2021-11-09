/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: skissm/service/e2ee_service.proto */

#ifndef PROTOBUF_C_skissm_2fservice_2fe2ee_5fservice_2eproto__INCLUDED
#define PROTOBUF_C_skissm_2fservice_2fe2ee_5fservice_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "skissm/e2ee_protocol_msg.pb-c.h"
#include "skissm/register_user_request_payload.pb-c.h"
#include "skissm/delete_user_request_payload.pb-c.h"
#include "skissm/get_pre_key_bundle_request_payload.pb-c.h"
#include "skissm/publish_spk_request_payload.pb-c.h"
#include "skissm/e2ee_message.pb-c.h"
#include "skissm/create_group_request_payload.pb-c.h"
#include "skissm/add_group_members_request_payload.pb-c.h"
#include "skissm/remove_group_members_request_payload.pb-c.h"
#include "skissm/get_group_request_payload.pb-c.h"
#include "skissm/service/dto/response_data.pb-c.h"
#include "skissm/service/dto/event_data_request.pb-c.h"
#include "skissm/service/dto/login_request.pb-c.h"
#include "skissm/service/dto/logout_request.pb-c.h"
#include "skissm/service/dto/connect_request.pb-c.h"



/* --- enums --- */


/* --- messages --- */

/* --- per-message closures --- */


/* --- services --- */

typedef struct Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service;
struct Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service
{
  ProtobufCService base;
  void (*communicate)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                      const Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *input,
                      Org__E2eelab__Skissm__Proto__E2eeProtocolMsg_Closure closure,
                      void *closure_data);
  void (*connect)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                  const Org__E2eelab__Server__Grpc__ConnectRequest *input,
                  Org__E2eelab__Skissm__Proto__E2eeProtocolMsg_Closure closure,
                  void *closure_data);
  void (*login)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                const Org__E2eelab__Server__Grpc__Auth__LoginRequest *input,
                Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                void *closure_data);
  void (*logout)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                 const Org__E2eelab__Server__Grpc__Auth__LogoutRequest *input,
                 Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                 void *closure_data);
  void (*register_user)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                        const Org__E2eelab__Skissm__Proto__RegisterUserRequestPayload *input,
                        Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                        void *closure_data);
  void (*delete_user)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                      const Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload *input,
                      Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                      void *closure_data);
  void (*get_pre_key_bundle)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                             const Org__E2eelab__Skissm__Proto__GetPreKeyBundleRequestPayload *input,
                             Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                             void *closure_data);
  void (*publish_spk)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                      const Org__E2eelab__Skissm__Proto__PublishSpkRequestPayload *input,
                      Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                      void *closure_data);
  void (*send_one2_one_msg)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                            const Org__E2eelab__Skissm__Proto__E2eeMessage *input,
                            Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                            void *closure_data);
  void (*create_group)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                       const Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload *input,
                       Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                       void *closure_data);
  void (*add_group_members)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                            const Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload *input,
                            Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                            void *closure_data);
  void (*remove_group_members)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                               const Org__E2eelab__Skissm__Proto__RemoveGroupMembersRequestPayload *input,
                               Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                               void *closure_data);
  void (*get_group)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                    const Org__E2eelab__Skissm__Proto__GetGroupRequestPayload *input,
                    Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                    void *closure_data);
  void (*send_group_msg)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                         const Org__E2eelab__Skissm__Proto__E2eeMessage *input,
                         Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                         void *closure_data);
  void (*get_event_data)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                         const Org__E2eelab__Server__Grpc__EventDataRequest *input,
                         Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                         void *closure_data);
};
typedef void (*Org__E2eelab__Server__Grpc__E2ee__E2EEService_ServiceDestroy)(Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__init (Org__E2eelab__Server__Grpc__E2ee__E2EEService_Service *service,
                                                           Org__E2eelab__Server__Grpc__E2ee__E2EEService_ServiceDestroy destroy);
#define ORG__E2EELAB__SERVER__GRPC__E2EE__E2_EESERVICE__BASE_INIT \
    { &org__e2eelab__server__grpc__e2ee__e2_eeservice__descriptor, protobuf_c_service_invoke_internal, NULL }
#define ORG__E2EELAB__SERVER__GRPC__E2EE__E2_EESERVICE__INIT(function_prefix__) \
    { ORG__E2EELAB__SERVER__GRPC__E2EE__E2_EESERVICE__BASE_INIT,\
      function_prefix__ ## communicate,\
      function_prefix__ ## connect,\
      function_prefix__ ## login,\
      function_prefix__ ## logout,\
      function_prefix__ ## register_user,\
      function_prefix__ ## delete_user,\
      function_prefix__ ## get_pre_key_bundle,\
      function_prefix__ ## publish_spk,\
      function_prefix__ ## send_one2_one_msg,\
      function_prefix__ ## create_group,\
      function_prefix__ ## add_group_members,\
      function_prefix__ ## remove_group_members,\
      function_prefix__ ## get_group,\
      function_prefix__ ## send_group_msg,\
      function_prefix__ ## get_event_data  }
void org__e2eelab__server__grpc__e2ee__e2_eeservice__communicate(ProtobufCService *service,
                                                                 const Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *input,
                                                                 Org__E2eelab__Skissm__Proto__E2eeProtocolMsg_Closure closure,
                                                                 void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__connect(ProtobufCService *service,
                                                             const Org__E2eelab__Server__Grpc__ConnectRequest *input,
                                                             Org__E2eelab__Skissm__Proto__E2eeProtocolMsg_Closure closure,
                                                             void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__login(ProtobufCService *service,
                                                           const Org__E2eelab__Server__Grpc__Auth__LoginRequest *input,
                                                           Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                           void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__logout(ProtobufCService *service,
                                                            const Org__E2eelab__Server__Grpc__Auth__LogoutRequest *input,
                                                            Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                            void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__register_user(ProtobufCService *service,
                                                                   const Org__E2eelab__Skissm__Proto__RegisterUserRequestPayload *input,
                                                                   Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                                   void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__delete_user(ProtobufCService *service,
                                                                 const Org__E2eelab__Skissm__Proto__DeleteUserRequestPayload *input,
                                                                 Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                                 void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__get_pre_key_bundle(ProtobufCService *service,
                                                                        const Org__E2eelab__Skissm__Proto__GetPreKeyBundleRequestPayload *input,
                                                                        Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                                        void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__publish_spk(ProtobufCService *service,
                                                                 const Org__E2eelab__Skissm__Proto__PublishSpkRequestPayload *input,
                                                                 Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                                 void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__send_one2_one_msg(ProtobufCService *service,
                                                                       const Org__E2eelab__Skissm__Proto__E2eeMessage *input,
                                                                       Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                                       void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__create_group(ProtobufCService *service,
                                                                  const Org__E2eelab__Skissm__Proto__CreateGroupRequestPayload *input,
                                                                  Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                                  void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__add_group_members(ProtobufCService *service,
                                                                       const Org__E2eelab__Skissm__Proto__AddGroupMembersRequestPayload *input,
                                                                       Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                                       void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__remove_group_members(ProtobufCService *service,
                                                                          const Org__E2eelab__Skissm__Proto__RemoveGroupMembersRequestPayload *input,
                                                                          Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                                          void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__get_group(ProtobufCService *service,
                                                               const Org__E2eelab__Skissm__Proto__GetGroupRequestPayload *input,
                                                               Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                               void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__send_group_msg(ProtobufCService *service,
                                                                    const Org__E2eelab__Skissm__Proto__E2eeMessage *input,
                                                                    Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                                    void *closure_data);
void org__e2eelab__server__grpc__e2ee__e2_eeservice__get_event_data(ProtobufCService *service,
                                                                    const Org__E2eelab__Server__Grpc__EventDataRequest *input,
                                                                    Org__E2eelab__Server__Grpc__ResponseData_Closure closure,
                                                                    void *closure_data);

/* --- descriptors --- */

extern const ProtobufCServiceDescriptor org__e2eelab__server__grpc__e2ee__e2_eeservice__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_skissm_2fservice_2fe2ee_5fservice_2eproto__INCLUDED */
