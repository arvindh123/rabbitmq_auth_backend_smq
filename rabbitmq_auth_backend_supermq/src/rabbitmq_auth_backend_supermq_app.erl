%%%-------------------------------------------------------------------
%% @doc rabbitmq_auth_backend_supermq_app application
%% @end
%%%-------------------------------------------------------------------

-module(rabbitmq_auth_backend_supermq_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    SmqGrpcConfig =
        case application:get_env(smq_grpc, config, undefined) of
            undefined ->
                logger:warning(
                    "smq_grpc.config is not found in env, using default smq_grpc.config"
                ),
                smq_auth:default_grpc_config();
            SmqGrpcConfigMap ->
                logger:info("SmqGrpcConfigMap ~p~n", [SmqGrpcConfigMap]),
                case smq_auth:convert_grpc_config(SmqGrpcConfigMap) of
                    {error, Reason} ->
                        logger:warning(
                            "failed to smq_grpc.config to smq_grpc_config record , using default smq_grpc.config, error: ~p",
                            [Reason]
                        ),
                        smq_auth:default_grpc_config();
                    ConvertedConfig ->
                        logger:notice(
                            "loaded smq_grpc.config from conf: ~p",
                            [ConvertedConfig]
                        ),
                        ConvertedConfig
                end
        end,
    smq_auth:init_smq_grpc(SmqGrpcConfig),

    rabbitmq_auth_backend_supermq_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
