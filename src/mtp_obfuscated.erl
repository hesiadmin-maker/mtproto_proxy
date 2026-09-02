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
-define(MAX_PADDING_SIZE, 32).
-define(MIN_PADDING_SIZE, 4).

%% Records
-record(st,
        {encrypt :: any(),                      % aes state
         decrypt :: any(),                      % aes state
         padding_enabled = true :: boolean(),   % padding toggle
         tls_simulation = false :: boolean(),   % TLS simulation mode
         packet_counter = 0 :: non_neg_integer() % packet counter for timing
        }).

-opaque codec() :: #st{}.

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Creates a new obfuscated client with standard parameters
-spec client_create(binary(), atom(), integer()) ->
    {binary(), {binary(), binary()}, {binary(), binary()}, codec()}.
client_create(Secret, Protocol, DcId) ->
    client_create(crypto:strong_rand_bytes(?SEED_SIZE), Secret, Protocol, DcId, #{}).

%% @doc Creates a new obfuscated client with custom seed
-spec client_create(binary(), binary(), atom(), integer()) ->
    {binary(), {binary(), binary()}, {binary(), binary()}, codec()}.
client_create(Seed, Secret, Protocol, DcId) ->
    client_create(Seed, Secret, Protocol, DcId, #{}).

%% @doc Creates a new obfuscated client with options
%% Options:
%%   - padding_enabled: boolean() - enable/disable random padding (default: true)
%%   - tls_simulation: boolean() - enable TLS-like traffic patterns (default: false)
%%   - min_padding: integer() - minimum padding bytes (default: 4)
%%   - max_padding: integer() - maximum padding bytes (default: 32)
-spec client_create(binary(), binary(), atom(), integer(), map()) ->
    {binary(), {binary(), binary()}, {binary(), binary()}, codec()}.
client_create(HexSecret, Protocol, DcId, Options) when byte_size(HexSecret) == 32 ->
    client_create(crypto:strong_rand_bytes(?SEED_SIZE), 
                  mtp_handler:unhex(HexSecret), 
                  Protocol, DcId, Options);
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

    %% Generate keys with enhanced entropy
    {EncKey, EncIv, DecKey, DecIv} = generate_keys(Raw, Secret),
    
    %% Create codec with options
    Codec0 = new(EncKey, EncIv, DecKey, DecIv),
    Codec = apply_options(Codec0, Options),
    
    %% Encrypt header with optional padding simulation
    {EncryptedHeader, Codec1} = encrypt_header(Raw, Codec),
    
    {EncryptedHeader, 
     {EncKey, EncIv},
     {DecKey, DecIv},
     Codec1}.

%% @doc Creates new obfuscated stream from header
-spec from_header(binary(), binary()) -> 
    {ok, integer(), atom(), codec()} | {error, term()}.
from_header(Header, Secret) when byte_size(Header) == ?HEADER_SIZE ->
    try
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
        padding_enabled = true,
        tls_simulation = false,
        packet_counter = 0
    }.

%% @doc Encrypts data with optional padding and TLS simulation
-spec encrypt(iodata(), codec()) -> {binary(), codec()}.
encrypt(Data, #st{encrypt = Enc, packet_counter = Counter} = St) ->
    %% Apply DPI resistance techniques
    {ProcessedData, St1} = apply_dpi_resistance(Data, St),
    
    %% Encrypt processed data
    {Enc1, Encrypted} = crypto_stream_encrypt(Enc, ProcessedData),
    
    {Encrypted, St1#st{
        encrypt = Enc1,
        packet_counter = Counter + 1
    }}.

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
    
    %% Remove padding if enabled
    {UnpaddedData, St2} = remove_padding(Decrypted, St1),
    
    case UnpaddedData of
        <<>> -> {incomplete, St2};
        _ -> {ok, UnpaddedData, Tail, St2}
    end.

%% @doc Encodes a packet for sending
-spec encode_packet(iodata(), codec()) -> {iodata(), codec()}.
encode_packet(Msg, St) ->
    encrypt(Msg, St).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @doc Generates encryption keys with enhanced entropy
generate_keys(Raw, Secret) ->
    %% Encryption key (for client -> server)
    <<_:8/binary, DecKeySeed:?KEY_LEN/binary, DecIv:?IV_LEN/binary, _/binary>> = Raw,
    DecKey = crypto:hash('sha256', <<DecKeySeed:?KEY_LEN/binary, Secret:16/binary>>),
    
    %% Decryption key (for server -> client)
    <<_:8/binary, EncKeySeed:?KEY_LEN/binary, EncIv:?IV_LEN/binary, _/binary>> = Raw,
    EncKey = crypto:hash('sha256', <<EncKeySeed:?KEY_LEN/binary, Secret:16/binary>>),
    
    %% Add additional entropy mixing
    MixedEncKey = mix_key(EncKey, DecKeySeed),
    MixedDecKey = mix_key(DecKey, EncKeySeed),
    
    {MixedEncKey, EncIv, MixedDecKey, DecIv}.

%% @doc Mixes keys for additional entropy
mix_key(Key, AdditionalEntropy) ->
    crypto:hash('sha256', <<Key:32/binary, AdditionalEntropy:32/binary>>).

%% @doc Applies DPI resistance techniques
apply_dpi_resistance(Data, #st{padding_enabled = true} = St) ->
    %% Add random padding
    PaddingSize = random_padding_size(),
    Padding = crypto:strong_rand_bytes(PaddingSize),
    
    %% Add length prefix
    DataBinary = iolist_to_binary(Data),
    DataSize = byte_size(DataBinary),
    PaddedData = <<DataSize:16, DataBinary/binary, Padding/binary>>,
    
    %% Optionally simulate TLS patterns
    case St#st.tls_simulation of
        true -> simulate_tls_pattern(PaddedData, St);
        false -> {PaddedData, St}
    end;
apply_dpi_resistance(Data, St) ->
    %% No padding, just add length prefix
    DataBinary = iolist_to_binary(Data),
    DataSize = byte_size(DataBinary),
    {<<DataSize:16, DataBinary/binary>>, St}.

%% @doc Generates random padding size
random_padding_size() ->
    rand:uniform(?MAX_PADDING_SIZE - ?MIN_PADDING_SIZE) + ?MIN_PADDING_SIZE.

%% @doc Simulates TLS-like traffic patterns
simulate_tls_pattern(Data, St) ->
    %% Add TLS record header simulation
    ContentType = case St#st.packet_counter rem 3 of
        0 -> <<16#16>>; % Handshake
        1 -> <<16#17>>; % Application data
        _ -> <<16#15>>  % Alert
    end,
    Version = <<3, 3>>, % TLS 1.2
    Length = byte_size(Data),
    
    %% Sometimes add dummy handshake messages
    case random_dummy_handshake() of
        true ->
            DummyHandshake = generate_dummy_handshake(),
            TLSData = <<ContentType/binary, Version/binary, 
                        (Length + byte_size(DummyHandshake)):16, 
                        Data/binary, DummyHandshake/binary>>,
            {TLSData, St};
        false ->
            TLSData = <<ContentType/binary, Version/binary, Length:16, Data/binary>>,
            {TLSData, St}
    end.

%% @doc Randomly decides to add dummy handshake
random_dummy_handshake() ->
    rand:uniform(10) == 1. % 10% chance

%% @doc Generates dummy TLS handshake data
generate_dummy_handshake() ->
    %% Create realistic-looking TLS handshake data
    HandshakeType = <<16#01>>, % Client Hello
    Length = rand:uniform(100) + 50,
    RandomData = crypto:strong_rand_bytes(Length),
    <<HandshakeType/binary, Length:24, RandomData/binary>>.

%% @doc Removes padding from decrypted data
remove_padding(Data, #st{padding_enabled = true} = St) ->
    case Data of
        <<Size:16, Payload:Size/binary, _Padding/binary>> ->
            {Payload, St};
        <<Size:16, _/binary>> when Size > byte_size(Data) - 2 ->
            {<<>>, St}; % Incomplete packet
        _ ->
            {Data, St#st{padding_enabled = false}} % Fallback
    end;
remove_padding(Data, St) ->
    case Data of
        <<Size:16, Payload:Size/binary, _/binary>> ->
            {Payload, St};
        _ ->
            {Data, St}
    end.

%% @doc Applies codec options
apply_options(Codec, Options) ->
    PaddingEnabled = maps:get(padding_enabled, Options, true),
    TLSSimulation = maps:get(tls_simulation, Options, false),
    
    Codec#st{
        padding_enabled = PaddingEnabled,
        tls_simulation = TLSSimulation
    }.

%% @doc Encrypts header with optional DPI resistance
encrypt_header(Raw, #st{encrypt = Enc} = St) ->
    {Enc1, Encrypted} = crypto_stream_encrypt(Enc, Raw),
    
    %% Extract encrypted portion
    <<RawL:56/binary, EncryptedPart:8/binary>> = Encrypted,
    
    %% Construct final header
    FinalHeader = <<RawL:56/binary, EncryptedPart:8/binary>>,
    
    {FinalHeader, St#st{encrypt = Enc1}}.

%% @doc Initializes encryption key from header
init_up_encrypt(Bin, Secret) ->
    <<_:8/binary, ToRev:(?KEY_LEN + ?IV_LEN)/binary, _/binary>> = Bin,
    Rev = bin_rev(ToRev),
    <<KeySeed:?KEY_LEN/binary, IV:?IV_LEN/binary>> = Rev,
    Key = crypto:hash('sha256', <<KeySeed:?KEY_LEN/binary, Secret:16/binary>>),
    {Key, IV}.

%% @doc Initializes decryption key from header
init_up_decrypt(Bin, Secret) ->
    <<_:8/binary, KeySeed:?KEY_LEN/binary, IV:?IV_LEN/binary, _/binary>> = Bin,
    Key = crypto:hash('sha256', <<KeySeed:?KEY_LEN/binary, Secret:16/binary>>),
    {Key, IV}.

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

padding_test() ->
    Secret = crypto:strong_rand_bytes(16),
    DcId = 4,
    Protocol = mtp_secure,
    {_, _, _, Codec} = client_create(Secret, Protocol, DcId, #{
        padding_enabled => true,
        tls_simulation => false
    }),
    
    %% Test encryption with padding
    TestData = <<"Hello, World!">>,
    {Encrypted, _Codec1} = encrypt(TestData, Codec),
    
    %% Encrypted data should be larger than original due to padding
    ?assert(byte_size(Encrypted) > byte_size(TestData) + 2).

tls_simulation_test() ->
    Secret = crypto:strong_rand_bytes(16),
    DcId = 4,
    Protocol = mtp_secure,
    {_, _, _, Codec} = client_create(Secret, Protocol, DcId, #{
        padding_enabled => true,
        tls_simulation => true
    }),
    
    %% Test encryption with TLS simulation
    TestData = <<"Hello, World!">>,
    {Encrypted, _Codec1} = encrypt(TestData, Codec),
    
    %% Should be even larger due to TLS header
    ?assert(byte_size(Encrypted) > byte_size(TestData) + 5).

-endif.
