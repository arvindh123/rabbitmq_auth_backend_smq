%%%-------------------------------------------------------------------
%% @doc rabbitmq_auth_backend_smq_config_parser
%% @end
%%%-------------------------------------------------------------------

-module(rabbitmq_auth_backend_smq_config_parser).
-export([parse_ip_port_list/1]).

parse_ip_port_list(ConfigStr) ->
    % Split by comma and remove whitespace
    Entries = [string:trim(Entry) || Entry <- string:split(ConfigStr, ",", all)],
    lists:map(fun parse_ip_port_entry/1, Entries).

parse_ip_port_entry(Entry) ->
    case string:split(Entry, ":") of
        [IPStr, PortStr] ->
            IP = parse_ip_address(string:trim(IPStr)),
            Port = parse_port(string:trim(PortStr)),
            {IP, Port};
        _ ->
            error({invalid_format, Entry})
    end.

parse_ip_address("any") ->
    any;
parse_ip_address(IPStr) ->
    case inet:parse_address(IPStr) of
        {ok, IP} -> IP;
        {error, _} -> error({invalid_ip, IPStr})
    end.

parse_port("any") ->
    any;
parse_port(PortStr) ->
    try list_to_integer(PortStr) of
        Port when Port > 0, Port =< 65535 -> Port;
        _ -> error({invalid_port, PortStr})
    catch
        error:badarg -> error({invalid_port, PortStr})
    end.
