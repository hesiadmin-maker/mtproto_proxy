%%% @author Sergey <me@seriyps.ru>
%%% @copyright (C) 2018, Sergey
%%% @doc
%%% MTProto proxy encryption and packet layer; "obfuscated2" protocol lib
%%% Enhanced version with improved DPI resistance
%%% @end
%%% Created : 29 May 2018 by Sergey <me@seriyps.ru>
%%% Enhanced: 2024 with DPI resistance improvements

-module(mtp_obfuscated).
-behaviour(mtp_codec).

%% API
-export([from_header/2,
         new/4,
         encrypt/2,
         decrypt/2,
         try_decode_packet/2,
         encode_packet/2
        ]).
-export([bin_rev/1]).
-export([client_create/3,
         client_create/4,
         client_create/5]).

-export_type([codec/0]).

%% Defines
-define(APP, mtproto_proxy).
-define(KEY_LEN, 32).
-define(IV_LEN, 16).
-define(HEADER_SIZE, 64).
-define(SEED_SIZE, 58).
-define(SECRET_SIZE, 16).

%% Records
-record(st,
        {encrypt :: any(),                      % aes state
         decrypt :: any(),                      % aes state
         tls_simulation = false :: boolean(),   % TLS simulation mode
         packet_counter = 0 :: non_neg_integer(), % packet counter
         handshake_complete = false :: boolean() % track handshake state
        }).

-opaque codec() :: #st{}.

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Creates a new obfuscated client with standard parameters
-spec client_create(binary(), atom(), integer()) ->
    {binary(), {binary(), binary()}, {binary(), binary()}, codec()}.
client_create(Secret, Protocol, DcId) ->
    Seed = crypto:strong_rand_bytes(?SEED_SIZE),
    client_create(Seed, Secret, Protocol, DcId, #{tls_simulation => false}).

%% @doc Creates a new obfuscated client with custom seed
-spec client_create(binary(), binary(), atom(), integer()) ->
    {binary(), {binary(), binary()}, {binary(), binary()}, codec()}.
client_create(Seed, Secret, Protocol, DcId) ->
    client_create(Seed, Secret, Protocol, DcId, #{tls_simulation => false}).

%% @doc Creates a new obfuscated client with options
%% Options:
%%   - tls_simulation: boolean() - enable TLS-like traffic patterns (default: false)
-spec client_create(binary(), binary(), atom(), integer(), map()) ->
    {binary(), {binary(), binary()}, {binary(), binary()}, codec()}.
client_create(Seed, Secret, Protocol, DcId, Options) 
    when byte_size(Seed) == ?SEED_SIZE,
         byte_size(Secret) == ?SECRET_SIZE,
         DcId >= -32768, DcId =< 32767,
         is_atom(Protocol),
         is_map(Options) ->
    
    <<L:56/binary, R:2/binary>> = Seed,
    ProtocolBin = encode_protocol(Protocol),
    DcIdBin = encode_dc_id(DcId),
    Raw = <<L:56/binary, ProtocolBin:4/binary, DcIdBin:2/binary, R:2/binary>>,

    %% Generate keys - original method
    {EncKey, EncIv, DecKey, DecIv} = generate_keys_original(Raw, Secret),
    
    %% Create codec
    Codec0 = new(EncKey, EncIv, DecKey, DecIv),
    Codec = apply_options(Codec0, Options),
    
    %% Encrypt header - original method
    {EncryptedHeader, Codec1} = encrypt_header_original(Raw, Codec),
    
    {EncryptedHeader, 
     {EncKey, EncIv},
     {DecKey, DecIv},
     Codec1}.

%% @doc Creates new obfuscated stream from header
-spec from_header(binary(), binary()) -> 
    {ok, integer(), atom(), codec()} | {error, term()}.
from_header(Header, Secret) when byte_size(Header) == ?HEADER_SIZE ->
    try
        %% Original key derivation
        {EncKey, EncIV} = init_up_encrypt_original(Header, Secret),
        {DecKey, DecIV} = init_up_decrypt_original(Header, Secret),
        St0 = new(EncKey, EncIV, DecKey, DecIV),
        {<<_:56/binary, Bin1:6/binary, _:2/binary>>, <<>>, St1} = decrypt(Header, St0),
        
        case get_protocol(Bin1) of
            {error, unknown_protocol} = Err ->
                Err;
            Protocol ->
                DcId = get_dc(Bin1),
                %% Mark handshake as complete
                St2 = St1#st{handshake_complete = true},
                {ok, DcId, Protocol, St2}
        end
    catch
        _:Error ->
            {error, {decryption_failed, Error}}
    end.

%% @doc Creates new codec with encryption keys
-spec new(binary(), binary(), binary(), binary()) -> codec().
new(EncKey, EncIV, DecKey, DecIV) ->
    #st{
        decrypt = crypto_stream_init('aes_ctr', DecKey, DecIV),
        encrypt = crypto_stream_init('aes_ctr', EncKey, EncIV),
        tls_simulation = false,
        packet_counter = 0,
        handshake_complete = false
    }.

%% @doc Encrypts data with DPI resistance
-spec encrypt(iodata(), codec()) -> {binary(), codec()}.
encrypt(Data, #st{encrypt = Enc, packet_counter = Counter} = St) ->
    %% Apply DPI resistance only after handshake
    case St#st.handshake_complete of
        false ->
            %% During handshake - use original encryption
            {Enc1, Encrypted} = crypto_stream_encrypt(Enc, Data),
            {Encrypted, St#st{encrypt = Enc1, packet_counter = Counter + 1}};
        true ->
            %% After handshake - apply DPI resistance
            {ProcessedData, St1} = apply_dpi_resistance(Data, St),
            {Enc1, Encrypted} = crypto_stream_encrypt(Enc, ProcessedData),
            {Encrypted, St1#st{encrypt = Enc1, packet_counter = Counter + 1}}
    end.

%% @doc Decrypts data
-spec decrypt(iodata(), codec()) -> {binary(), binary(), codec()}.
decrypt(Encrypted, #st{decrypt = Dec} = St) ->
    {Dec1, Data} = crypto_stream_encrypt(Dec, Encrypted),
    {Data, <<>>, St#st{decrypt = Dec1}}.

%% @doc Attempts to decode a complete packet from buffer
-spec try_decode_packet(iodata(), codec()) -> 
    {ok, binary(), binary(), codec()} | {incomplete, codec()}.
try_decode_packet(Encrypted, St) ->
    {Decrypted, Tail, St1} = decrypt(Encrypted, St),
    
    %% Only process DPI resistance after handshake
    case St1#st.handshake_complete of
        true ->
            {UnprocessedData, St2} = remove_dpi_resistance(Decrypted, St1),
            case UnprocessedData of
                <<>> -> {incomplete, St2};
                _ -> {ok, UnprocessedData, Tail, St2}
            end;
        false ->
            %% During handshake - return as-is
            {ok, Decrypted, Tail, St1}
    end.

%% @doc Encodes a packet for sending
-spec encode_packet(iodata(), codec()) -> {iodata(), codec()}.
encode_packet(Msg, St) ->
    encrypt(Msg, St).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @doc Original key generation for compatibility
generate_keys_original(Raw, Secret) ->
    %% init_up_encrypt (client -> server)
    <<_:8/binary, ToRev:(?KEY_LEN + ?IV_LEN)/binary, _/binary>> = Raw,
    Rev = bin_rev(ToRev),
    <<KeySeed:?KEY_LEN/binary, IV:?IV_LEN/binary>> = Rev,
    EncKey = crypto:hash('sha256', <<KeySeed:?KEY_LEN/binary, Secret:16/binary>>),
    
    %% init_up_decrypt (server -> client)
    <<_:8/binary, DecKeySeed:?KEY_LEN/binary, DecIV:?IV_LEN/binary, _/binary>> = Raw,
    DecKey = crypto:hash('sha256', <<DecKeySeed:?KEY_LEN/binary, Secret:16/binary>>),
    
    {EncKey, IV, DecKey, DecIV}.

%% @doc Original header encryption for compatibility
encrypt_header_original(Raw, #st{encrypt = Enc} = St) ->
    {Enc1, Encrypted} = crypto_stream_encrypt(Enc, Raw),
    <<RawL:56/binary, EncryptedPart:8/binary>> = Encrypted,
    FinalHeader = <<RawL:56/binary, EncryptedPart:8/binary>>,
    {FinalHeader, St#st{encrypt = Enc1}}.

%% @doc Original key initialization for compatibility
init_up_encrypt_original(Bin, Secret) ->
    <<_:8/binary, ToRev:(?KEY_LEN + ?IV_LEN)/binary, _/binary>> = Bin,
    Rev = bin_rev(ToRev),
    <<KeySeed:?KEY_LEN/binary, IV:?IV_LEN/binary>> = Rev,
    Key = crypto:hash('sha256', <<KeySeed:?KEY_LEN/binary, Secret:16/binary>>),
    {Key, IV}.

init_up_decrypt_original(Bin, Secret) ->
    <<_:8/binary, KeySeed:?KEY_LEN/binary, IV:?IV_LEN/binary, _/binary>> = Bin,
    Key = crypto:hash('sha256', <<KeySeed:?KEY_LEN/binary, Secret:16/binary>>),
    {Key, IV}.

%% @doc Applies DPI resistance techniques (TLS simulation)
apply_dpi_resistance(Data, #st{tls_simulation = true} = St) ->
    %% TLS simulation - wrap data in TLS-like records
    simulate_tls_pattern(Data, St);
apply_dpi_resistance(Data, St) ->
    %% Default: add random padding within MTProto frame
    add_random_padding(Data, St).

%% @doc Adds random padding to MTProto packets
add_random_padding(Data, St) ->
    DataBinary = iolist_to_binary(Data),
    
    %% Add padding in a way that's compatible with MTProto
    %% MTProto uses length-prefixed framing, so we add padding after the length
    case DataBinary of
        <<Len:32/little, Rest/binary>> when Len > 0, Len < 16777216 ->
            %% This is a transport packet - add padding
            PaddingSize = rand:uniform(16),  % 0-15 bytes padding
            Padding = crypto:strong_rand_bytes(PaddingSize),
            NewLen = Len + PaddingSize,
            <<NewLen:32/little, Rest/binary, Padding/binary>>;
        _ ->
            %% Not a standard packet - leave as-is
            DataBinary
    end,
    {Result, St}.

%% @doc Simulates TLS-like traffic patterns
simulate_tls_pattern(Data, St) ->
    %% Add TLS record header simulation
    ContentType = case St#st.packet_counter rem 3 of
        0 -> <<16#16>>; % Handshake
        1 -> <<16#17>>; % Application data
        _ -> <<16#15>>  % Alert
    end,
    Version = <<3, 3>>, % TLS 1.2
    DataBinary = iolist_to_binary(Data),
    Length = byte_size(DataBinary),
    
    %% Sometimes add dummy handshake messages
    case rand:uniform(10) == 1 of
        true ->
            DummyHandshake = generate_dummy_handshake(),
            TLSData = <<ContentType/binary, Version/binary, 
                        (Length + byte_size(DummyHandshake)):16, 
                        DataBinary/binary, DummyHandshake/binary>>,
            {TLSData, St};
        false ->
            TLSData = <<ContentType/binary, Version/binary, Length:16, DataBinary/binary>>,
            {TLSData, St}
    end.

%% @doc Generates dummy TLS handshake data
generate_dummy_handshake() ->
    %% Create realistic-looking TLS handshake data
    HandshakeType = <<16#01>>, % Client Hello
    Length = rand:uniform(100) + 50,
    RandomData = crypto:strong_rand_bytes(Length),
    <<HandshakeType/binary, Length:24, RandomData/binary>>.

%% @doc Removes DPI resistance from decrypted data
remove_dpi_resistance(Data, #st{tls_simulation = true} = St) ->
    %% Remove TLS simulation
    remove_tls_pattern(Data, St);
remove_dpi_resistance(Data, St) ->
    %% Remove padding
    remove_random_padding(Data, St).

%% @doc Removes random padding from MTProto packets
remove_random_padding(Data, St) ->
    case Data of
        <<Len:32/little, Rest/binary>> when Len > 0 ->
            case Rest of
                <<ActualData:Len/binary, _Padding/binary>> ->
                    {ActualData, St};
                _ ->
                    {<<>>, St}  % Incomplete
            end;
        _ ->
            {Data, St}
    end.

%% @doc Removes TLS pattern from data
remove_tls_pattern(Data, St) ->
    case Data of
        <<_:5/binary, Length:16, TLSData/binary>> ->
            case TLSData of
                <<ActualData:Length/binary, _Rest/binary>> ->
                    {ActualData, St};
                _ ->
                    {<<>>, St}  % Incomplete
            end;
        _ ->
            {Data, St}
    end.

%% @doc Applies codec options
apply_options(Codec, Options) ->
    TLSSimulation = maps:get(tls_simulation, Options, false),
    
    Codec#st{
        tls_simulation = TLSSimulation
    }.

%% @doc Encodes protocol identifier
encode_protocol(mtp_abridged) -> <<16#ef, 16#ef, 16#ef, 16#ef>>;
encode_protocol(mtp_intermediate) -> <<16#ee, 16#ee, 16#ee, 16#ee>>;
encode_protocol(mtp_secure) -> <<16#dd, 16#dd, 16#dd, 16#dd>>.

%% @doc Encodes DC ID
encode_dc_id(DcId) -> <<DcId:16/signed-little-integer>>.

%% @doc Extracts protocol from header
get_protocol(<<16#ef, 16#ef, 16#ef, 16#ef, _:2/binary>>) -> mtp_abridged;
get_protocol(<<16#ee, 16#ee, 16#ee, 16#ee, _:2/binary>>) -> mtp_intermediate;
get_protocol(<<16#dd, 16#dd, 16#dd, 16#dd, _:2/binary>>) -> mtp_secure;
get_protocol(_) -> {error, unknown_protocol}.

%% @doc Extracts DC ID from header
get_dc(<<_:4/binary, DcId:16/signed-little-integer>>) -> DcId.

%% @doc Reverses binary
bin_rev(Bin) when is_binary(Bin) ->
    Size = byte_size(Bin),
    << <<(binary:at(Bin, Size - I - 1))>> || I <- lists:seq(0, Size - 1) >>.

%% @doc Initializes crypto stream
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

handshake_test() ->
    Secret = crypto:strong_rand_bytes(16),
    DcId = 4,
    Protocol = mtp_secure,
    {Packet, _, _, CliCodec} = client_create(Secret, Protocol, DcId),
    {ok, DcId, Protocol, SrvCodec} = from_header(Packet, Secret),
    
    %% Test handshake packet (should not be modified)
    TestData = <<"handshake_data">>,
    {Encrypted, _} = encrypt(TestData, CliCodec),
    {Decrypted, <<>>, _} = decrypt(Encrypted, SrvCodec),
    ?assertEqual(TestData, Decrypted).

-endif.
