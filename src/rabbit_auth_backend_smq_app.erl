%%%-------------------------------------------------------------------
%% @doc rabbit_auth_backend_smq application
%% @end
%%%-------------------------------------------------------------------

-module(rabbit_auth_backend_smq_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    rabbit_auth_backend_smq_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
