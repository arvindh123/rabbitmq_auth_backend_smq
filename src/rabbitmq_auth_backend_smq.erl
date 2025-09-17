%%%-------------------------------------------------------------------
%% @doc rabbitmq_auth_backend_smq
%% @end
%%%-------------------------------------------------------------------

-module(rabbitmq_auth_backend_smq).

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

%%--------------------------------------------------------------------

getSocketInfo(AuthProps) ->
    case proplists:get_value(sockOrAddr, AuthProps, undefined) of
        undefined ->
            {socket_information_notfound};
        Socket ->
            case inet:peernameSocket(Socket) of
                {ok, {IP, Port}} ->
                    {ok, {IP, Port}};
                _ ->
                    {socket_information_notfound}
            end
    end.

-spec user_login_authentication(rabbit_types:username(), [term()] | map()) ->
    {'ok', rabbit_types:auth_user()}
    | {'refused', string(), [any()]}
    | {'error', any()}.
user_login_authentication(Username, AuthProps) ->
    logger:debug("At user_login_authentication Username: ~p Socket: ~p AuthProps: ~p", [
        Username, getSocketInfo(AuthProps), AuthProps
    ]),

    case extract_password(AuthProps) of
        {error, missing_password} ->
            logger:debug("Password missing or empty", []),
            {refused, "Missing password", []};
        {ok, Password} ->
            do_client_authn(Username, Password, AuthProps)
    end.

do_client_authn(Username, Password, AuthProps) ->
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
            Tags = [rabbit_data_coercion:to_atom(ID)],
            Resp = #auth_user{
                username = Username,
                tags = Tags,
                impl = fun() -> proplists:delete(username, AuthProps) end
            },
            logger:debug("Auth OK,  Returning Resp : ~p", [Resp]),
            {ok, Resp};
        {error, unauthenticated} ->
            {refused, "Denied by the SMQ Client AuthN", []};
        {error, {Code, Msg}} ->
            MsgStr = lists:flatten(
                io_lib:format("SMQ Client AuthN failed: Code: ~p Msg: ~p", [Code, Msg])
            ),
            logger:info("failed to authenticate : ~p", [MsgStr]),
            {refused, MsgStr, []};
        {error, Reason} ->
            MsgStr = lists:flatten(
                io_lib:format("SMQ Client AuthN failed: Reason: ~p ", [term_to_string(Reason)])
            ),
            logger:info("failed to authenticate : ~p", [MsgStr]),
            {refused, MsgStr, []};
        {grpc_error, Details} ->
            MsgStr = lists:flatten(
                io_lib:format("SMQ Client AuthN failed: Reason: ~p ", [term_to_string(Details)])
            ),
            logger:info("failed to authenticate : ~p", [MsgStr]),
            {refused, MsgStr, []};
        Other ->
            MsgStr = lists:flatten(
                io_lib:format("SMQ Client AuthN failed: got unknown : ~p ", [
                    term_to_string(Other)
                ])
            ),
            logger:error("failed to authenticate : ~p", [MsgStr]),
            {error, {bad_response, MsgStr}}
    end.

user_login_authorization(Username, AuthProps) ->
    case user_login_authentication(Username, AuthProps) of
        {ok, #auth_user{impl = Impl}} ->
            {ok, Impl};
        Else ->
            Else
    end.

check_vhost_access(#auth_user{username = Username, tags = Tags}, VHost, undefined) ->
    do_check_vhost_access(Username, Tags, VHost, "", undefined);
check_vhost_access(
    #auth_user{username = Username, tags = Tags},
    VHost,
    AuthzData = #{peeraddr := PeerAddr}
) when is_map(AuthzData) ->
    AuthzData1 = maps:remove(peeraddr, AuthzData),
    Ip = parse_peeraddr(PeerAddr),
    do_check_vhost_access(Username, Tags, VHost, Ip, AuthzData1).

do_check_vhost_access(Username, Tags, VHost, Ip, AuthzData) ->
    logger:debug("At do_check_vhost_access Username: ~p Tags: ~p VHost: ~p Ip: ~p AuthzData: ~p", [
        Username, Tags, VHost, Ip, AuthzData
    ]),
    true.

check_resource_access(
    #auth_user{username = Username, tags = Tags},
    #resource{
        virtual_host = VHost,
        kind = Type,
        name = Name
    },
    Permission,
    AuthzContext
) ->
    logger:debug(
        "At check_resource_access Username: ~p Tags: ~p VHost:  ~p  Type: ~p Name: ~p Permission: ~p Socket ~p AuthzContext: ~p",
        [
            Username,
            Tags,
            VHost,
            Type,
            Name,
            Permission,
            getSocketInfo(AuthzContext),
            AuthzContext
        ]
    ),
    true.

check_topic_access(
    #auth_user{username = Username, tags = Tags},
    #resource{virtual_host = VHost, kind = topic = Type, name = Name},
    Permission,
    Context
) ->
    %% Extract routing_key safely
    RoutingKey =
        case maps:get(routing_key, Context, undefined) of
            undefined ->
                %% if not defined return return empty string
                <<"">>;
            RK when is_binary(RK) ->
                RK
        end,
    logger:debug(
        "At check_topic_access: Username: ~p Tags: ~p VHost: ~p  Type: ~p Name: ~p Permission: ~p RoutingKey ~p Socket ~p Context: ~p",
        [
            Username,
            Tags,
            VHost,
            Type,
            Name,
            Permission,
            RoutingKey,
            getSocketInfo(Context),
            Context
        ]
    ),
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
                    MsgStr = lists:flatten(
                        io_lib:format("Unauthorized", [])
                    ),
                    logger:debug("failed to authorize : ~p", [MsgStr]),
                    false;
                {error, {Code, Msg}} ->
                    MsgStr = lists:flatten(
                        io_lib:format("SMQ Client AuthZ failed: Code: ~p Msg: ~p", [Code, Msg])
                    ),
                    logger:debug("failed to authorize : ~p", [MsgStr]),
                    false;
                {error, Reason} ->
                    MsgStr = lists:flatten(
                        io_lib:format("SMQ Client AuthZ failed: Reason: ~p ", [
                            term_to_string(Reason)
                        ])
                    ),
                    logger:info("failed to authorize : ~p", [MsgStr]),
                    false;
                {grpc_error, Details} ->
                    MsgStr = lists:flatten(
                        io_lib:format("SMQ Client AuthZ failed: Reason: ~p ", [
                            term_to_string(Details)
                        ])
                    ),
                    logger:info("failed to authorize : ~p", [MsgStr]),
                    false;
                Other ->
                    MsgStr = lists:flatten(
                        io_lib:format("SMQ Client AuthZ failed: got unknown : ~p ", [
                            term_to_string(Other)
                        ])
                    ),
                    logger:info("failed to authorize : ~p", [MsgStr]),
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

-spec extract_password(Props :: [term()] | map()) ->
    {ok, binary()}
    | {error, missing_password}.
extract_password(Props) when is_list(Props) ->
    case proplists:get_value(password, Props, undefined) of
        undefined ->
            {error, missing_password};
        % empty binary
        <<>> ->
            {error, missing_password};
        Password when is_binary(Password) ->
            {ok, Password};
        Password when is_list(Password) ->
            % convert list to binary
            {ok, list_to_binary(Password)}
    end.

-spec term_to_string(term()) -> string().
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
    {ok, Path} = application:get_env(rabbitmq_auth_backend_smq, PathName),
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

-spec handle_inet_ntoa_peeraddr(
    {error, term()} | string(),
    inet:ip_address() | unknown
) ->
    string().
handle_inet_ntoa_peeraddr({error, einval}, PeerAddr) ->
    rabbit_data_coercion:to_list(PeerAddr);
handle_inet_ntoa_peeraddr(PeerAddrStr, _PeerAddr0) ->
    PeerAddrStr.
