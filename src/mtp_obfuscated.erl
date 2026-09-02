%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% MTProto proxy encryption and packet layer; "obfuscated2" protocol lib
%%% Enhanced with maximum DPI resistance features
%%% @end

-module(mtp_obfuscated).
-behaviour(mtp_codec).

-export([from_header/2,
         new/4,
         encrypt/2,
         decrypt/2,
         try_decode_packet/2,
         encode_packet/2,
         bin_rev/1,
         client_create/3,
         client_create/4,
         set_stealth_mode/2,
         set_pattern/2,
         enable_padding/1,
         disable_padding/1,
         enable_fragmentation/2,
         disable_fragmentation/1,
         enable_timing_obfuscation/2,
         disable_timing_obfuscation/1
        ]).

-export_type([codec/0]).

-record(st,
        {
         encrypt :: any(),                      % aes state
         decrypt :: any(),                      % aes state
         stealth_mode = false :: boolean(),     % enable/disable stealth
         pattern = auto :: auto | http | websocket | binary | random,
         padding = false :: boolean(),          % enable/disable padding
         fragment_size = 0 :: integer(),        % 0 = disabled
         timing_interval = 0 :: integer(),      % 0 = disabled
         current_pattern :: atom() | undefined,
         packet_counter = 0 :: integer(),
         session_id :: binary() | undefined
        }).

-define(APP, mtproto_proxy).
-define(KEY_LEN, 32).
-define(IV_LEN, 16).
-define(PADDING_BLOCK, 256).
-define(DEFAULT_FRAGMENT_SIZE, 512).

-opaque codec() :: #st{}.

%%%===================================================================
%%% API
%%%===================================================================

client_create(Secret, Protocol, DcId) ->
    client_create(crypto:strong_rand_bytes(58),
                  Secret, Protocol, DcId).

-spec client_create(binary(), binary(), mtp_codec:packet_codec(), integer()) ->
                           {Packet,
                            {EncKey, EncIv},
                            {DecKey, DecIv},
                            CliCodec} when
      Packet :: binary(),
      EncKey :: binary(),
      EncIv :: binary(),
      DecKey :: binary(),
      DecIv :: binary(),
      CliCodec :: codec().
client_create(Seed, HexSecret, Protocol, DcId) when byte_size(HexSecret) == 32 ->
    client_create(Seed, mtp_handler:unhex(HexSecret), Protocol, DcId);
client_create(Seed, Secret, Protocol, DcId) when byte_size(Seed) == 58,
                                          byte_size(Secret) == 16,
                                          DcId >= -32768,
                                          DcId =< 32767,
                                          is_atom(Protocol) ->
    <<L:56/binary, R:2/binary>> = Seed,
    ProtocolBin = encode_protocol(Protocol),
    DcIdBin = encode_dc_id(DcId),
    Raw = <<L:56/binary, ProtocolBin:4/binary, DcIdBin:2/binary, R:2/binary>>,

    %% init_up_encrypt/2
    <<_:8/binary, ToRev:(?KEY_LEN + ?IV_LEN)/binary, _/binary>> = Raw,
    <<DecKeySeed:?KEY_LEN/binary, DecIv:?IV_LEN/binary>> = bin_rev(ToRev),
    DecKey = crypto:hash('sha256', <<DecKeySeed:?KEY_LEN/binary, Secret:16/binary>>),

    %% init_up_decrypt/2
    <<_:8/binary, EncKeySeed:?KEY_LEN/binary, EncIv:?IV_LEN/binary, _/binary>> = Raw,
    EncKey = crypto:hash('sha256', <<EncKeySeed:?KEY_LEN/binary, Secret:16/binary>>),

    Codec = new(EncKey, EncIv, DecKey, DecIv),
    {<<_:56/binary, Encrypted:8/binary>>, Codec1} = encrypt(Raw, Codec),
    <<RawL:56/binary, _:8/binary>> = Raw,
    Packet = <<RawL:56/binary, Encrypted:8/binary>>,
    {Packet,
     {EncKey, EncIv},
     {DecKey, DecIv},
     Codec1}.

%% @doc creates new obfuscated stream (MTProto proxy format)
-spec from_header(binary(), binary()) -> {ok, integer(), mtp_codec:packet_codec(), codec()}
                                             | {error, unknown_protocol}.
from_header(Header, Secret) when byte_size(Header) == 64  ->
    {EncKey, EncIV} = init_up_encrypt(Header, Secret),
    {DecKey, DecIV} = init_up_decrypt(Header, Secret),
    St = new(EncKey, EncIV, DecKey, DecIV),
    {<<_:56/binary, Bin1:6/binary, _:2/binary>>, <<>>, St1} = decrypt(Header, St),
    case get_protocol(Bin1) of
        {error, unknown_protocol} = Err ->
            Err;
        Protocol ->
            DcId = get_dc(Bin1),
            {ok, DcId, Protocol, St1}
    end.

%% @doc Configuration functions for stealth mode
-spec set_stealth_mode(codec(), boolean()) -> codec().
set_stealth_mode(St, Enabled) when is_boolean(Enabled) ->
    SessionId = case Enabled of
        true -> crypto:strong_rand_bytes(16);
        false -> undefined
    end,
    St#st{stealth_mode = Enabled, session_id = SessionId}.

-spec set_pattern(codec(), atom()) -> codec().
set_pattern(St, Pattern) when Pattern =:= auto;
                              Pattern =:= http;
                              Pattern =:= websocket;
                              Pattern =:= binary;
                              Pattern =:= random ->
    St#st{pattern = Pattern}.

-spec enable_padding(codec()) -> codec().
enable_padding(St) ->
    St#st{padding = true}.

-spec disable_padding(codec()) -> codec().
disable_padding(St) ->
    St#st{padding = false}.

-spec enable_fragmentation(codec(), integer()) -> codec().
enable_fragmentation(St, FragmentSize) when is_integer(FragmentSize), FragmentSize > 0 ->
    St#st{fragment_size = FragmentSize}.

-spec disable_fragmentation(codec()) -> codec().
disable_fragmentation(St) ->
    St#st{fragment_size = 0}.

-spec enable_timing_obfuscation(codec(), integer()) -> codec().
enable_timing_obfuscation(St, Interval) when is_integer(Interval), Interval > 0 ->
    St#st{timing_interval = Interval}.

-spec disable_timing_obfuscation(codec()) -> codec().
disable_timing_obfuscation(St) ->
    St#st{timing_interval = 0}.

new(EncKey, EncIV, DecKey, DecIV) ->
    #st{
       decrypt = crypto_stream_init('aes_ctr', DecKey, DecIV),
       encrypt = crypto_stream_init('aes_ctr', EncKey, EncIV)
      }.

-spec encrypt(iodata(), codec()) -> {binary(), codec()}.
encrypt(Data, #st{encrypt = Enc} = St) ->
    {Enc1, Encrypted} = crypto_stream_encrypt(Enc, Data),
    {Encrypted, St#st{encrypt = Enc1}}.

-spec decrypt(iodata(), codec()) -> {binary(), binary(), codec()}.
decrypt(Encrypted, #st{decrypt = Dec} = St) ->
    {Dec1, Data} = crypto_stream_encrypt(Dec, Encrypted),
    {Data, <<>>, St#st{decrypt = Dec1}}.

-spec try_decode_packet(iodata(), codec()) -> {ok, Decoded :: binary(), Tail :: binary(), codec()}
                                                  | {incomplete, codec()}.
try_decode_packet(Encrypted, St) ->
    {Decrypted, Tail, St1} = decrypt(Encrypted, St),
    case St1#st.stealth_mode of
        true ->
            %% Unwrap stealth layers
            Unwrapped = unwrap_stealth(Decrypted, St1),
            {ok, Unwrapped, Tail, St1};
        false ->
            {ok, Decrypted, Tail, St1}
    end.

-spec encode_packet(iodata(), codec()) -> {iodata(), codec()}.
encode_packet(Msg, #st{stealth_mode = true} = S) ->
    %% Apply stealth layers before encryption
    Processed = apply_stealth_layers(Msg, S),
    St1 = update_packet_counter(S),
    encrypt(Processed, St1);
encode_packet(Msg, S) ->
    encrypt(Msg, S).

%%%===================================================================
%%% Internal functions - Stealth mode
%%%===================================================================

%% Apply stealth layers based on current pattern
apply_stealth_layers(Data, #st{pattern = Pattern, 
                               padding = Padding,
                               fragment_size = FragSize,
                               packet_counter = Counter} = St) ->
    
    %% Layer 1: Add padding if enabled
    Padded = case Padding of
        true -> add_padding(Data);
        false -> Data
    end,
    
    %% Layer 2: Apply pattern-based wrapping
    ActualPattern = select_pattern(Pattern, Counter),
    Wrapped = case ActualPattern of
        http ->
            wrap_as_http(Padded);
        websocket ->
            wrap_as_websocket(Padded);
        binary ->
            Padded;
        _ ->
            Padded
    end,
    
    %% Layer 3: Fragment if enabled
    case FragSize of
        0 -> Wrapped;
        _ -> fragment_data(Wrapped, FragSize)
    end.

%% Unwrap stealth layers
unwrap_stealth(Data, #st{pattern = Pattern,
                        padding = Padding,
                        packet_counter = Counter} = St) ->
    
    %% Remove fragmentation (reassembled at TCP level, so not needed here)
    Unfragmented = Data,
    
    %% Remove pattern wrapping
    ActualPattern = select_pattern(Pattern, Counter),
    Unwrapped = case ActualPattern of
        http ->
            unwrap_http(Unfragmented);
        websocket ->
            unwrap_websocket(Unfragmented);
        binary ->
            Unfragmented;
        _ ->
            Unfragmented
    end,
    
    %% Remove padding if enabled
    case Padding of
        true -> remove_padding(Unwrapped);
        false -> Unwrapped
    end.

%% Pattern selection
select_pattern(auto, Counter) ->
    Patterns = [http, websocket, binary],
    lists:nth((Counter rem length(Patterns)) + 1, Patterns);
select_pattern(random, _) ->
    Patterns = [http, websocket, binary],
    lists:nth(rand:uniform(length(Patterns)), Patterns);
select_pattern(Pattern, _) ->
    Pattern.

%% Padding functions
add_padding(Data) ->
    Len = byte_size(Data),
    PadLen = (?PADDING_BLOCK - (Len rem ?PADDING_BLOCK)) rem ?PADDING_BLOCK,
    Pad = case PadLen of
        0 -> crypto:strong_rand_bytes(?PADDING_BLOCK);
        N -> crypto:strong_rand_bytes(N)
    end,
    <<PadLen:16, Pad/binary, Data/binary>>.

remove_padding(<<PadLen:16, _:PadLen/binary, Data/binary>>) ->
    Data;
remove_padding(Data) ->
    Data.

%% HTTP-like wrapping
wrap_as_http(Data) ->
    Methods = ["GET", "POST", "PUT", "PATCH"],
    Paths = ["/api/v1/data", "/static/app.js", "/health", "/metrics",
             "/api/v2/users", "/assets/main.css", "/favicon.ico"],
    Versions = ["HTTP/1.1", "HTTP/2"],
    Hosts = ["api.example.com", "cdn.example.org", "static.example.net",
             "data.example.io", "service.example.co"],
    
    Method = lists:nth(rand:uniform(length(Methods)), Methods),
    Path = lists:nth(rand:uniform(length(Paths)), Paths),
    Version = lists:nth(rand:uniform(length(Versions)), Versions),
    Host = lists:nth(rand:uniform(length(Hosts)), Hosts),
    
    Header = list_to_binary([
        Method, " ", Path, " ", Version, "\r\n",
        "Host: ", Host, "\r\n",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n",
        "Accept: */*\r\n",
        "Accept-Language: en-US,en;q=0.9\r\n",
        "Cache-Control: no-cache\r\n",
        "Pragma: no-cache\r\n\r\n"
    ]),
    
    <<Header/binary, Data/binary>>.

unwrap_http(Data) ->
    case binary:split(Data, <<"\r\n\r\n">>) of
        [_, Body] -> Body;
        [_] -> Data
    end.

%% WebSocket-like wrapping
wrap_as_websocket(Data) ->
    Opcode = case rand:uniform(100) of
        N when N =< 70 -> 2;  %% binary frame
        N when N =< 90 -> 1;  %% text frame
        _ -> 10               %% pong frame
    end,
    
    Len = byte_size(Data),
    Frame = case Len of
        L when L < 126 ->
            <<1:1, 0:3, Opcode:4, 0:1, L:7, Data/binary>>;
        L when L =< 65535 ->
            <<1:1, 0:3, Opcode:4, 0:1, 126:7, L:16, Data/binary>>;
        L ->
            <<1:1, 0:3, Opcode:4, 0:1, 127:7, L:64, Data/binary>>
    end,
    
    %% Add mask bit and mask key (client-to-server frames must be masked)
    MaskKey = crypto:strong_rand_bytes(4),
    MaskedData = mask_data(Data, MaskKey),
    MaskedLen = byte_size(MaskedData),
    
    case MaskedLen of
        L when L < 126 ->
            <<1:1, 0:3, Opcode:4, 1:1, L:7, MaskKey/binary, MaskedData/binary>>;
        L when L =< 65535 ->
            <<1:1, 0:3, Opcode:4, 1:1, 126:7, L:16, MaskKey/binary, MaskedData/binary>>;
        L ->
            <<1:1, 0:3, Opcode:4, 1:1, 127:7, L:64, MaskKey/binary, MaskedData/binary>>
    end.

unwrap_websocket(Data) ->
    case Data of
        <<1:1, _:3, _:4, 1:1, Len:7, MaskKey:4/binary, MaskedData:Len/binary, _/binary>> ->
            unmask_data(MaskedData, MaskKey);
        <<1:1, _:3, _:4, 1:1, 126:7, Len:16, MaskKey:4/binary, MaskedData:Len/binary, _/binary>> ->
            unmask_data(MaskedData, MaskKey);
        <<1:1, _:3, _:4, 1:1, 127:7, Len:64, MaskKey:4/binary, MaskedData:Len/binary, _/binary>> ->
            unmask_data(MaskedData, MaskKey);
        _ ->
            Data
    end.

%% WebSocket masking
mask_data(Data, MaskKey) ->
    mask_data(Data, MaskKey, 0, <<>>).

mask_data(<<>>, _, _, Acc) ->
    Acc;
mask_data(<<Byte:8, Rest/binary>>, MaskKey, Index, Acc) ->
    MaskByte = binary:at(MaskKey, Index rem 4),
    MaskedByte = Byte bxor MaskByte,
    mask_data(Rest, MaskKey, Index + 1, <<Acc/binary, MaskedByte:8>>).

unmask_data(Data, MaskKey) ->
    mask_data(Data, MaskKey).

%% Fragmentation
fragment_data(Data, FragSize) when byte_size(Data) > FragSize ->
    <<First:FragSize/binary, Rest/binary>> = Data,
    [First | fragment_data(Rest, FragSize)];
fragment_data(Data, _) ->
    [Data].

%% Packet counter update
update_packet_counter(#st{packet_counter = Counter} = St) ->
    St#st{packet_counter = Counter + 1}.

%%%===================================================================
%%% Protocol helpers
%%%===================================================================

init_up_encrypt(Bin, Secret) ->
    <<_:8/binary, ToRev:(?KEY_LEN + ?IV_LEN)/binary, _/binary>> = Bin,
    Rev = bin_rev(ToRev),
    <<KeySeed:?KEY_LEN/binary, IV:?IV_LEN/binary>> = Rev,
    Key = crypto:hash('sha256', <<KeySeed:?KEY_LEN/binary, Secret:16/binary>>),
    {Key, IV}.

init_up_decrypt(Bin, Secret) ->
    <<_:8/binary, KeySeed:?KEY_LEN/binary, IV:?IV_LEN/binary, _/binary>> = Bin,
    Key = crypto:hash('sha256', <<KeySeed:?KEY_LEN/binary, Secret:16/binary>>),
    {Key, IV}.

encode_protocol(mtp_abridged) ->
    <<16#ef, 16#ef, 16#ef, 16#ef>>;
encode_protocol(mtp_intermediate) ->
    <<16#ee, 16#ee, 16#ee, 16#ee>>;
encode_protocol(mtp_secure) ->
    <<16#dd, 16#dd, 16#dd, 16#dd>>.

encode_dc_id(DcId) ->
    <<DcId:16/signed-little-integer>>.

get_protocol(<<16#ef, 16#ef, 16#ef, 16#ef, _:2/binary>>) ->
    mtp_abridged;
get_protocol(<<16#ee, 16#ee, 16#ee, 16#ee, _:2/binary>>) ->
    mtp_intermediate;
get_protocol(<<16#dd, 16#dd, 16#dd, 16#dd, _:2/binary>>) ->
    mtp_secure;
get_protocol(_) ->
    {error, unknown_protocol}.

get_dc(<<_:4/binary, DcId:16/signed-little-integer>>) ->
    DcId.

%%%===================================================================
%%% Helpers
%%%===================================================================

bin_rev(Bin) ->
    list_to_binary(lists:reverse(binary_to_list(Bin))).

-if(?OTP_RELEASE >= 23).
crypto_stream_init(aes_ctr, Key, IV) ->
    crypto:crypto_init(aes_256_ctr, Key, IV, []).

crypto_stream_encrypt(State, Data) ->
    {State, crypto:crypto_update(State, Data)}.

-else.
crypto_stream_init(Algo, Key, IV) ->
    crypto:stream_init(Algo, Key, IV).

crypto_stream_encrypt(State, Data) ->
    crypto:stream_encrypt(State, Data).

-endif.

%%%===================================================================
%%% Tests
%%%===================================================================

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

client_server_test() ->
    Secret = crypto:strong_rand_bytes(16),
    DcId = 4,
    Protocol = mtp_secure,
    {Packet, _, _, _CliCodec} = client_create(Secret, Protocol, DcId),
    Srv = from_header(Packet, Secret),
    ?assertMatch({ok, DcId, Protocol, _}, Srv).

stealth_mode_test() ->
    Secret = crypto:strong_rand_bytes(16),
    DcId = 4,
    Protocol = mtp_secure,
    {Packet, _, _, CliCodec} = client_create(Secret, Protocol, DcId),
    {ok, _, _, SrvCodec} = from_header(Packet, Secret),
    
    %% Enable stealth mode
    CliCodec1 = set_stealth_mode(CliCodec, true),
    CliCodec2 = enable_padding(CliCodec1),
    CliCodec3 = set_pattern(CliCodec2, http),
    
    SrvCodec1 = set_stealth_mode(SrvCodec, true),
    SrvCodec2 = enable_padding(SrvCodec1),
    SrvCodec3 = set_pattern(SrvCodec2, http),
    
    %% Test data
    TestData = <<"Hello, World!">>,
    
    %% Encode and decode
    {Encoded, CliCodec4} = encode_packet(TestData, CliCodec3),
    {ok, Decoded, _, _} = try_decode_packet(Encoded, SrvCodec3),
    
    ?assertEqual(TestData, Decoded).

-endif.
