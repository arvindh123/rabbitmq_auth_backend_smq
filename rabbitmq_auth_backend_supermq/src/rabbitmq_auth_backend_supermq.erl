%%%-------------------------------------------------------------------
%% @doc rabbitmq_auth_backend_supermq
%% @end
%%%-------------------------------------------------------------------

-module(rabbitmq_auth_backend_supermq).

-include_lib("rabbit_common/include/rabbit.hrl").
-include_lib("smq_auth/include/smq_auth.hrl").

-behaviour(rabbit_authn_backend).
-behaviour(rabbit_authz_backend).

-export([description/0, p/1, q/1, join_tags/1]).
-export([
    user_login_authentication/2,
    user_login_authorization/2,
    check_vhost_access/3,
    check_resource_access/4,
    check_topic_access/4,
    expiry_timestamp/1
]).

description() ->
    [{name, <<"SMQ Auth"/utf8>>}, {description, <<"SuperMQ Authentication / Authorization"/utf8>>}].

-record(user_ctx, {
    %% Which auth backend was used
    auth :: internal | external,
    %% Server side (the RabbitMQ listener socket)

    %% {A,B,C,D} or {K0,...,K7}
    server_ip :: inet:ip_address() | undefined,
    %% integer 0..65535
    server_port :: inet:port_number() | undefined,

    %% Client side (the connecting peer)
    client_ip :: inet:ip_address() | undefined,
    client_port :: inet:port_number() | undefined
}).

-define(BLANK_PASSWORD_REJECTION_MESSAGE,
    "user '~ts' attempted to log in with a blank password, which is prohibited by the internal authN backend. "
    "To use TLS/x509 certificate-based authentication, see the rabbitmq_auth_mechanism_ssl plugin and configure the client to use the EXTERNAL authentication mechanism. "
    "Alternatively change the password for the user to be non-blank."
).

-define(USER_CTX_REJECTION_MESSAGE,
    "Unable to build authentication context for user ~ts . Connection rejected , Reason: ~p"
).

-define(USER_CTX_SOCK_ERR_REJECTION_MESSAGE,
    "Unable to retrieve socket information (IP/port) for authentication for user ~ts . Connection rejected, Reason: ~p"
).

-define(SMQ_AUTHN_DENIED, "smq authentication denied for user ~ts").
-define(SMQ_AUTHN_FAILED_WITH_CODE_MSG, "smq authentication failed for user ~ts code ~p msg: ~p").
-define(SMQ_AUTHN_FAILED_WITH_REASON, "smq authentication failed for user ~ts reason ~p ").
-define(SMQ_AUTHN_FAILED_WITH_GRPC_REASON,
    "smq authentication failed for user ~ts grpc reason ~p "
).

-define(SMQ_AUTHN_FAILED_FOR_OTHER_REASON,
    "smq authentication failed for user ~ts other reason ~p "
).

%%--------------------------------------------------------------------
%% Get server-side socket IP and port
% get_server_ip_port(AuthProps) ->
%     ExtractedSock =
%         case AuthProps of
%             %% proplist
%             AuthPorpsList when is_list(AuthPorpsList) ->
%                 proplists:get_value(sockOrAddr, AuthPorpsList, undefined);
%             %% map
%             #{sockOrAddr := S} ->
%                 S;
%             _ ->
%                 undefined
%         end,
%     case ExtractedSock of
%         undefined ->
%             {not_found};
%         Sock when is_port(Sock) ->
%             %% Normal case: Sock is a port (#Port<...>)
%             case rabbit_net:sockname(Sock) of
%                 {ok, {IP, Port}} -> {ok, {IP, Port}};
%                 Error -> {error, Error}
%             end;
%         Other ->
%             {error, {unexpected_sock_value, Other}}
%     end.
%% InternalIpPortList example: [{{127,0,0,1}, any}, {{10,0,0,5}, 5672}]
% is_internal_ip_port({IP, Port}, InternalIpPortList) ->
%     lists:any(
%         fun
%             ({any, any}) -> true;
%             ({AIP, any}) -> AIP =:= IP;
%             ({AIP, APort}) -> AIP =:= IP andalso APort =:= Port
%         end,
%         InternalIpPortList
%     ).
%% Build a user_ctx record from AuthProps

-spec build_user_ctx(
    AuthProps :: list() | map(),
    FindAuthTypeFun :: fun(
        (
            inet:ip_address() | undefined,
            inet:port_number() | undefined,
            inet:ip_address() | undefined,
            inet:port_number() | undefined
        ) -> internal | external
    )
) ->
    {ok, #user_ctx{}} | {error, term()}.
build_user_ctx(AuthProps, FindAuthTypeFun) ->
    %% Extract socket from AuthProps (supports proplist or map)
    ExtractedSock =
        case AuthProps of
            %% proplist
            AuthPorpsList when is_list(AuthPorpsList) ->
                proplists:get_value(sockOrAddr, AuthPorpsList, undefined);
            %% map
            #{sockOrAddr := S} ->
                S;
            _ ->
                undefined
        end,
    case ExtractedSock of
        undefined ->
            AuthType = FindAuthTypeFun(undefined, undefined, undefined, undefined),
            {ok, #user_ctx{
                auth = AuthType,
                server_ip = undefined,
                server_port = undefined,
                client_ip = undefined,
                client_port = undefined
            }};
        Sock when is_port(Sock) ->
            case {rabbit_net:peername(Sock), rabbit_net:sockname(Sock)} of
                {{ok, {ClientIP, ClientPort}}, {ok, {ServerIP, ServerPort}}} ->
                    AuthType = FindAuthTypeFun(ServerIP, ServerPort, ClientIP, ClientPort),
                    {ok, #user_ctx{
                        auth = AuthType,
                        server_ip = ServerIP,
                        server_port = ServerPort,
                        client_ip = ClientIP,
                        client_port = ClientPort
                    }};
                Error ->
                    {error, Error}
            end;
        {sslsocket, _, _} = SslSock ->
            case {ssl:peername(SslSock), ssl:sockname(SslSock)} of
                {{ok, {ClientIP, ClientPort}}, {ok, {ServerIP, ServerPort}}} ->
                    AuthType = FindAuthTypeFun(ServerIP, ServerPort, ClientIP, ClientPort),
                    {ok, #user_ctx{
                        auth = AuthType,
                        server_ip = ServerIP,
                        server_port = ServerPort,
                        client_ip = ClientIP,
                        client_port = ClientPort
                    }};
                Error ->
                    {error, Error}
            end;
        Other ->
            {error, {unexpected_sock_value, Other}}
    end.

-spec user_login_authentication(rabbit_types:username(), [term()] | map()) ->
    {'ok', rabbit_types:auth_user()}
    | {'refused', string(), [any()]}
    | {'error', any()}.
user_login_authentication(Username, AuthProps) ->
    do_authn(Username, AuthProps).

-spec find_auth_type_fun(
    ServerIP :: inet:ip_address() | undefined,
    ServerPort :: inet:port_number() | undefined,
    ClientIP :: inet:ip_address() | undefined,
    ClientPort :: inet:port_number() | undefined
) -> internal | external.
find_auth_type_fun(ServerIP, ServerPort, _ClientIP, _ClientPort) ->
    %% Load allowed internal IP:Port tuples from config
    Allowed =
        case application:get_env(rabbitmq_auth_backend_supermq, internal_ip_ports) of
            {ok, List} when is_list(List) -> List;
            _ -> []
        end,

    case
        lists:any(
            fun({AllowedIP, AllowedPort}) ->
                ip_port_match(ServerIP, ServerPort, AllowedIP, AllowedPort)
            end,
            Allowed
        )
    of
        true -> internal;
        false -> external
    end.

%% @doc Match server IP and port against allowed IP and port patterns
%% Supports 'any' wildcard for both IP and port, and handles undefined values
-spec ip_port_match(
    ServerIP :: inet:ip_address() | undefined,
    ServerPort :: inet:port_number() | undefined,
    AllowedIP :: inet:ip_address() | any | undefined,
    AllowedPort :: inet:port_number() | any | undefined
) -> boolean().
ip_port_match(undefined, _, _, _) ->
    false;
ip_port_match(_, undefined, _, _) ->
    false;
ip_port_match(_ServerIP, _ServerPort, any, any) ->
    true;
ip_port_match(_ServerIP, ServerPort, any, AllowedPort) when ServerPort =/= undefined ->
    ServerPort =:= AllowedPort;
ip_port_match(ServerIP, _ServerPort, AllowedIP, any) when ServerIP =/= undefined ->
    ServerIP =:= AllowedIP;
ip_port_match(ServerIP, ServerPort, AllowedIP, AllowedPort) when
    ServerIP =/= undefined, ServerPort =/= undefined
->
    ServerIP =:= AllowedIP andalso ServerPort =:= AllowedPort.

do_authn(Username, AuthProps) ->
    logger:debug("At do_authn Username: ~p AuthProps: ~p UserCtx ~p", [
        Username, AuthProps, build_user_ctx(AuthProps, fun find_auth_type_fun/4)
    ]),
    case build_user_ctx(AuthProps, fun find_auth_type_fun/4) of
        {ok, #user_ctx{auth = internal} = UserCtx} ->
            do_internal_authn(Username, AuthProps, UserCtx);
        {ok, #user_ctx{auth = external} = UserCtx} ->
            do_external_client_authn(Username, AuthProps, UserCtx);
        {ok, #user_ctx{auth = Other}} ->
            {error, {unexpected_auth_type, Other}};
        {error, {sockname_failed, Reason}} ->
            {refused, ?USER_CTX_SOCK_ERR_REJECTION_MESSAGE, [Username, Reason]};
        {error, Reason} ->
            {refused, ?USER_CTX_REJECTION_MESSAGE, [Username, Reason]}
    end.

do_internal_authn(Username, AuthProps, UserCtx) ->
    case rabbit_auth_backend_internal:user_login_authentication(Username, AuthProps) of
        {ok, #auth_user{username = U, tags = Tags}} ->
            {ok, #auth_user{username = U, tags = Tags, impl = fun() -> UserCtx end}};
        Refused ->
            Refused
    end.

do_external_client_authn(Username, AuthProps, UserCtx) ->
    case lists:keyfind(password, 1, AuthProps) of
        {password, <<"">>} ->
            {refused, ?BLANK_PASSWORD_REJECTION_MESSAGE, [Username]};
        {password, ""} ->
            {refused, ?BLANK_PASSWORD_REJECTION_MESSAGE, [Username]};
        %% For cases when authenticating using an x.509 certificate
        {password, none} ->
            does_smq_client_exists(Username, AuthProps, UserCtx);
        {password, Cleartext} ->
            do_smq_client_authn(Username, Cleartext, AuthProps, UserCtx);
        false ->
            {refused, ?BLANK_PASSWORD_REJECTION_MESSAGE, [Username]}
    end.

do_smq_client_authn(Username, Password, _AuthProps, UserCtx) ->
    Req = #smq_client_authn_request{
        client_id =
            case Username of
                U when is_binary(U) -> binary_to_list(U);
                U when is_list(U) -> U
            end,
        client_key =
            case Password of
                P when is_binary(P) -> binary_to_list(P);
                P when is_list(P) -> P
            end
    },

    Result = catch smq_auth:client_authn(Req),
    case Result of
        {ok, ID} ->
            Resp = #auth_user{
                username = Username,
                tags = [],
                impl = fun() -> UserCtx end
            },
            logger:debug("Auth OK,  Returning Resp : ~p", [Resp]),
            {ok, Resp};
        {error, unauthenticated} ->
            {refused, ?SMQ_AUTHN_DENIED, [Username]};
        {error, {Code, Msg}} ->
            {refused, ?SMQ_AUTHN_FAILED_WITH_CODE_MSG, [Username, Code, Msg]};
        {error, Reason} ->
            {refused, ?SMQ_AUTHN_FAILED_WITH_REASON, [Username, Reason]};
        {grpc_error, Reason} ->
            {refused, ?SMQ_AUTHN_FAILED_WITH_GRPC_REASON, [Username, Reason]};
        Other ->
            {error, {bad_response, {?SMQ_AUTHN_FAILED_FOR_OTHER_REASON, [Username, Other]}}}
    end.

does_smq_client_exists(Username, _AuthProps, UserCtx) ->
    case smq_auth:check_client_exists(Username) of
        true ->
            Resp = #auth_user{
                username = Username,
                tags = [],
                impl = fun() -> UserCtx end
            },
            logger:debug("Auth OK,  Returning Resp : ~p", [Resp]),
            {ok, Resp};
        _ ->
            {refused, ?SMQ_AUTHN_DENIED, [Username]}
    end.

user_login_authorization(Username, AuthProps) ->
    case user_login_authentication(Username, AuthProps) of
        {ok, #auth_user{impl = Impl}} ->
            {ok, Impl};
        {ok, #auth_user{impl = Impl, tags = Tags}} ->
            {ok, Impl, Tags};
        Else ->
            Else
    end.

check_vhost_access(#auth_user{username = Username, tags = Tags, impl = Impl}, VHost, undefined) ->
    do_check_vhost_access(Username, Tags, Impl, VHost, "", undefined);
check_vhost_access(
    #auth_user{username = Username, tags = Tags, impl = Impl},
    VHost,
    AuthzData = #{peeraddr := PeerAddr}
) when is_map(AuthzData) ->
    AuthzData1 = maps:remove(peeraddr, AuthzData),
    Ip = parse_peeraddr(PeerAddr),
    do_check_vhost_access(Username, Tags, Impl, VHost, Ip, AuthzData1).

do_check_vhost_access(Username, Tags, Impl, VHost, Ip, AuthzData) ->
    logger:debug(
        "At do_check_vhost_access Username: ~p Tags: ~p Impl: ~p VHost: ~p Ip: ~p AuthzData: ~p", [
            Username, Tags, Impl(), VHost, Ip, AuthzData
        ]
    ),
    true.

check_resource_access(
    #auth_user{username = Username, tags = Tags, impl = Impl},
    #resource{
        virtual_host = VHost,
        kind = Type,
        name = Name
    },
    Permission,
    AuthzContext
) ->
    logger:debug(
        "At check_resource_access Username: ~p Tags: ~p Impl: ~p VHost:  ~p  Type: ~p Name: ~p Permission: ~p  AuthzContext: ~p",
        [
            Username,
            Tags,
            Impl(),
            VHost,
            Type,
            Name,
            Permission,
            AuthzContext
        ]
    ),
    true.

check_topic_access(
    #auth_user{username = Username, tags = Tags, impl = Impl} = User,
    #resource{virtual_host = VHost, kind = topic = Type, name = Name} = Resource,
    Permission,
    Context
) ->
    RoutingKey =
        case maps:get(routing_key, Context, undefined) of
            undefined ->
                %% if not defined return return empty string
                <<"">>;
            RK when is_binary(RK) ->
                RK
        end,
    %% Extract routing_key safely
    logger:debug(
        "At check_topic_access: Username: ~p Tags: ~p Impl: ~p VHost: ~p  Type: ~p Name: ~p Permission: ~p RoutingKey ~p Context: ~p",
        [
            Username,
            Tags,
            Impl(),
            VHost,
            Type,
            Name,
            Permission,
            RoutingKey,
            Context
        ]
    ),

    case Impl of
        Fun when is_function(Fun, 0) ->
            %% Call the function to get the user context
            UserCtx = Fun(),
            case is_record(UserCtx, user_ctx) of
                true ->
                    case UserCtx#user_ctx.auth of
                        external ->
                            do_smq_authz(
                                Username,
                                Tags,
                                UserCtx,
                                VHost,
                                Type,
                                Name,
                                Permission,
                                RoutingKey,
                                Context
                            );
                        internal ->
                            rabbit_auth_backend_internal:check_topic_access(
                                User, Resource, Permission, Context
                            )
                    end;
                false ->
                    logger:error(
                        "failed to check_topic_access Username: ~p Permission: ~p RoutingKey: ~p Reason: user context not found  Received context: ~p ",
                        [
                            Username, Permission, RoutingKey, UserCtx
                        ]
                    ),
                    false
            end;
        Other ->
            logger:error(
                "failed to check_topic_access  Username: ~p Permission: ~p RoutingKey: ~p Reason: implementation is not fun/0  Received implementation: ~p ",
                [
                    Username, Permission, RoutingKey, Other
                ]
            ),
            false
    end.

do_smq_authz(Username, _Tags, _Impl, _VHost, _Type, _Name, Permission, RoutingKey, _Context) ->
    case parse_topic_name(RoutingKey) of
        {match, DomainID, ChannelID} ->
            Req = #smq_client_authz_request{
                domain_id = DomainID,
                channel_id = ChannelID,
                client_id = binary_to_list(Username),
                client_type = client,
                client_key = "",
                type =
                    case Permission of
                        write -> publish;
                        read -> subscribe
                    end
            },
            logger:debug("Request Prepared : ~p", [Req]),

            Result = catch smq_auth:client_authz(Req),

            case Result of
                {ok} ->
                    true;
                {error, {unauthorized}} ->
                    logger:debug("unauthorized, Username: ~p Permission: ~p RoutingKey: ~p", [
                        Username, Permission, RoutingKey
                    ]),
                    false;
                {error, {Code, Msg}} ->
                    logger:notice(
                        "smq client authz failed : Username: ~p Permission: ~p RoutingKey: ~p Code: ~p Msg: ~p",
                        [
                            Username, Permission, RoutingKey, Code, Msg
                        ]
                    ),
                    false;
                {error, Reason} ->
                    logger:notice(
                        "smq client authz failed : Username: ~p Permission: ~p RoutingKey: ~p Reason: ~p",
                        [
                            Username, Permission, RoutingKey, Reason
                        ]
                    ),
                    false;
                {grpc_error, Reason} ->
                    logger:notice(
                        "smq client authz failed at grpc : Username: ~p Permission: ~p RoutingKey: ~p Reason: ~p",
                        [
                            Username, Permission, RoutingKey, Reason
                        ]
                    ),
                    false;
                Other ->
                    logger:error(
                        "smq client authz failed for unknown reason : Username: ~p Permission: ~p RoutingKey: ~p Unknown Reason: ~p",
                        [
                            Username, Permission, RoutingKey, Other
                        ]
                    ),
                    false
            end;
        {nomatch} ->
            MsgStr = lists:flatten(
                io_lib:format("Topic name does not match expected pattern: ~p", [RoutingKey])
            ),
            logger:debug("failed to authorize : ~p", [MsgStr]),
            false
    end.

expiry_timestamp(_) ->
    never.

%%--------------------------------------------------------------------

% already charlist
term_to_string(S) when is_list(S) -> S;
term_to_string(B) when is_binary(B) -> binary_to_list(B);
term_to_string(Other) -> lists:flatten(io_lib:format("~p", [Other])).

-spec parse_topic_name(Topic :: binary()) ->
    {match, DomainID :: string(), ChannelID :: string()}
    | {nomatch}.
parse_topic_name(Topic) ->
    %% Compile the regex
    Regex = <<"^m\\.([^\\.]+)\\.c\\.([^\\.]+)(?:\\..*)?$">>,
    case re:run(Topic, Regex, [{capture, all_but_first, list}]) of
        {match, [DomainID, ChannelID]} ->
            {match, DomainID, ChannelID};
        nomatch ->
            {nomatch}
    end.

p(PathName) ->
    {ok, Path} = application:get_env(rabbitmq_auth_backend_supermq, PathName),
    Path.

q(Args) ->
    string:join([escape(K, V) || {K, V} <- Args, not is_function(V)], "&").

escape(K, Map) when is_map(Map) ->
    string:join(
        [
            escape(
                rabbit_data_coercion:to_list(K) ++
                    "." ++
                    rabbit_data_coercion:to_list(Key),
                Value
            )
         || {Key, Value} <- maps:to_list(Map), not is_function(Value)
        ],
        "&"
    );
escape(K, V) ->
    rabbit_data_coercion:to_list(K) ++ "=" ++ rabbit_http_util:quote_plus(V).

join_tags([]) ->
    "";
join_tags(Tags) ->
    Strings = [rabbit_data_coercion:to_list(T) || T <- Tags],
    string:join(Strings, " ").

-spec parse_peeraddr(inet:ip_address() | unknown) -> string().
parse_peeraddr(unknown) ->
    rabbit_data_coercion:to_list(unknown);
parse_peeraddr(PeerAddr) ->
    handle_inet_ntoa_peeraddr(inet:ntoa(PeerAddr), PeerAddr).

-spec handle_inet_ntoa_peeraddr({'error', term()} | string(), inet:ip_address() | unknown) ->
    string().
handle_inet_ntoa_peeraddr({error, einval}, PeerAddr) ->
    rabbit_data_coercion:to_list(PeerAddr);
handle_inet_ntoa_peeraddr(PeerAddrStr, _PeerAddr0) ->
    PeerAddrStr.
