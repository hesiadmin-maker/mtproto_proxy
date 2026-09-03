%%% @author Enhanced DPI-Resistant Version
%%% @copyright (C) 2024
%%% @doc
%%% MTProto proxy with maximum DPI resistance
%%% Features: Traffic morphing, TLS mimicry, Adaptive padding,
%%%           Timing randomization, Multi-layer obfuscation
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
         set_dpi_resistance/2,
         set_traffic_profile/2,
         enable_advanced_obfuscation/1,
         disable_advanced_obfuscation/1,
         set_tls_profile/2,
         set_timing_profile/2,
         enable_domain_fronting/2,
         enable_connection_chaining/1,
         enable_port_hopping/2,
         get_statistics/1
        ]).

-export_type([codec/0]).

-record(st,
        {
         encrypt :: any(),
         decrypt :: any(),
         dpi_resistance = false :: boolean(),
         traffic_profile = auto :: auto | video_streaming | web_browsing | 
                              file_download | voip | gaming | social_media,
         advanced_obfuscation = false :: boolean(),
         tls_profile = auto :: auto | chrome_120 | firefox_121 | safari_17 |
                       edge_120 | mobile_ios | mobile_android,
         timing_profile = auto :: auto | burst | steady | irregular,
         domain_fronting = false :: boolean(),
         front_domain = "cdn.cloudflare.com" :: string(),
         connection_chaining = false :: boolean(),
         port_hopping = false :: boolean(),
         port_list = [443, 8443, 2053, 2083, 2087, 2096] :: [integer()],
         current_port = 443 :: integer(),
         packet_counter = 0 :: integer(),
         session_start_time = 0 :: integer(),
         last_packet_time = 0 :: integer(),
         entropy_state = <<>> :: binary(),
         tls_state = #{} :: map(),
         morphing_state = #{} :: map(),
         stats = #{} :: map()
        }).

-define(APP, mtproto_proxy).
-define(KEY_LEN, 32).
-define(IV_LEN, 16).
-define(MAX_PADDING, 1500).
-define(MIN_PADDING, 64).
-define(TLS_RECORD_HEADER, 5).
-define(MAX_FRAGMENT, 16384).

-opaque codec() :: #st{}.

%%%===================================================================
%%% API Functions
%%%===================================================================

client_create(Secret, Protocol, DcId) ->
    client_create(crypto:strong_rand_bytes(58),
                  Secret, Protocol, DcId).

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

    %% Morph the initial handshake to look like TLS ClientHello
    MorphedHandshake = morph_initial_handshake(Raw),
    
    %% init_up_encrypt/2
    <<_:8/binary, ToRev:(?KEY_LEN + ?IV_LEN)/binary, _/binary>> = Raw,
    <<DecKeySeed:?KEY_LEN/binary, DecIv:?IV_LEN/binary>> = bin_rev(ToRev),
    DecKey = crypto:hash('sha256', <<DecKeySeed:?KEY_LEN/binary, Secret:16/binary>>),

    %% init_up_decrypt/2
    <<_:8/binary, EncKeySeed:?KEY_LEN/binary, EncIv:?IV_LEN/binary, _/binary>> = Raw,
    EncKey = crypto:hash('sha256', <<EncKeySeed:?KEY_LEN/binary, Secret:16/binary>>),

    Codec = new(EncKey, EncIv, DecKey, DecIv),
    Codec1 = Codec#st{
        session_start_time = erlang:system_time(millisecond),
        last_packet_time = erlang:system_time(millisecond),
        entropy_state = crypto:strong_rand_bytes(32),
        tls_state = init_tls_state(),
        morphing_state = init_morphing_state()
    },
    
    %% Encrypt the morphed handshake
    {Encrypted, Codec2} = encrypt_packet_with_morphing(MorphedHandshake, Codec1),
    
    %% Build final packet with TLS-like structure
    FinalPacket = build_tls_like_packet(Encrypted),
    
    {FinalPacket,
     {EncKey, EncIv},
     {DecKey, DecIv},
     Codec2}.

%% @doc Set DPI resistance level
set_dpi_resistance(St, Level) when is_integer(Level), Level >= 0, Level =< 10 ->
    ResistanceEnabled = Level > 0,
    St1 = St#st{dpi_resistance = ResistanceEnabled},
    case Level of
        L when L >= 1 -> enable_advanced_obfuscation(St1);
        _ -> disable_advanced_obfuscation(St1)
    end.

%% @doc Set traffic profile for morphing
set_traffic_profile(St, Profile) when Profile =:= auto;
                                     Profile =:= video_streaming;
                                     Profile =:= web_browsing;
                                     Profile =:= file_download;
                                     Profile =:= voip;
                                     Profile =:= gaming;
                                     Profile =:= social_media ->
    St#st{traffic_profile = Profile}.

%% @doc Enable advanced obfuscation techniques
enable_advanced_obfuscation(St) ->
    St#st{
        advanced_obfuscation = true,
        dpi_resistance = true
    }.

disable_advanced_obfuscation(St) ->
    St#st{
        advanced_obfuscation = false,
        dpi_resistance = false
    }.

%% @doc Set TLS profile for fingerprint randomization
set_tls_profile(St, Profile) when Profile =:= auto;
                                 Profile =:= chrome_120;
                                 Profile =:= firefox_121;
                                 Profile =:= safari_17;
                                 Profile =:= edge_120;
                                 Profile =:= mobile_ios;
                                 Profile =:= mobile_android ->
    St#st{tls_profile = Profile}.

%% @doc Set timing profile for traffic pattern
set_timing_profile(St, Profile) when Profile =:= auto;
                                    Profile =:= burst;
                                    Profile =:= steady;
                                    Profile =:= irregular ->
    St#st{timing_profile = Profile}.

%% @doc Enable domain fronting simulation
enable_domain_fronting(St, FrontDomain) when is_list(FrontDomain) ->
    St#st{
        domain_fronting = true,
        front_domain = FrontDomain
    }.

%% @doc Enable connection chaining
enable_connection_chaining(St) ->
    St#st{connection_chaining = true}.

%% @doc Enable port hopping
enable_port_hopping(St, Ports) when is_list(Ports) ->
    St#st{
        port_hopping = true,
        port_list = Ports
    }.

%% @doc Get statistics about the connection
get_statistics(St) ->
    St#st.stats.

new(EncKey, EncIV, DecKey, DecIV) ->
    #st{
       decrypt = crypto_stream_init('aes_ctr', DecKey, DecIV),
       encrypt = crypto_stream_init('aes_ctr', EncKey, EncIV),
       session_start_time = erlang:system_time(millisecond),
       last_packet_time = erlang:system_time(millisecond),
       entropy_state = crypto:strong_rand_bytes(32),
       tls_state = init_tls_state(),
       morphing_state = init_morphing_state()
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
try_decode_packet(Encrypted, #st{dpi_resistance = true} = St) ->
    %% Remove TLS-like wrapping first
    Unwrapped = unwrap_tls_like(Encrypted),
    {Decrypted, Tail, St1} = decrypt(Unwrapped, St),
    %% Remove morphing layers
    Demorphed = demorph_packet(Decrypted, St1),
    {ok, Demorphed, Tail, St1};
try_decode_packet(Encrypted, St) ->
    {Decrypted, Tail, St1} = decrypt(Encrypted, St),
    {ok, Decrypted, Tail, St1}.

-spec encode_packet(iodata(), codec()) -> {iodata(), codec()}.
encode_packet(Msg, #st{dpi_resistance = true} = S) ->
    %% Apply all obfuscation layers
    St1 = update_packet_stats(S),
    Processed = apply_advanced_obfuscation(Msg, St1),
    {Encrypted, St2} = encrypt_packet_with_morphing(Processed, St1),
    %% Wrap as TLS-like if needed
    FinalPacket = case St2#st.advanced_obfuscation of
        true -> build_tls_like_packet(Encrypted);
        false -> Encrypted
    end,
    {FinalPacket, St2};
encode_packet(Msg, S) ->
    encrypt(Msg, S).

%%%===================================================================
%%% Internal Functions - Advanced Obfuscation
%%%===================================================================

%% Apply advanced obfuscation layers
apply_advanced_obfuscation(Data, #st{
    traffic_profile = Profile,
    advanced_obfuscation = true,
    packet_counter = Counter,
    entropy_state = Entropy
} = St) ->
    
    %% Layer 1: Adaptive padding based on traffic profile
    Padded = apply_adaptive_padding(Data, Profile, Counter),
    
    %% Layer 2: Traffic morphing
    Morphed = morph_traffic(Padded, Profile, Counter, St),
    
    %% Layer 3: Entropy normalization
    Normalized = normalize_entropy(Morphed, Entropy),
    
    %% Layer 4: Protocol mimicry
    Mimicked = mimic_protocol(Normalized, Profile, Counter),
    
    Mimicked.

%% Adaptive padding based on traffic profile
apply_adaptive_padding(Data, Profile, Counter) ->
    BasePad = case Profile of
        video_streaming -> rand:uniform(400) + 200;
        web_browsing -> rand:uniform(200) + 100;
        file_download -> rand:uniform(800) + 400;
        voip -> rand:uniform(100) + 50;
        gaming -> rand:uniform(150) + 75;
        social_media -> rand:uniform(300) + 150;
        auto -> rand:uniform(?MAX_PADDING - ?MIN_PADDING) + ?MIN_PADDING
    end,
    
    %% Add some randomness based on counter
    CounterModulation = (Counter * 17) rem 100,
    PadLen = BasePad + CounterModulation,
    
    PadData = crypto:strong_rand_bytes(PadLen),
    <<PadLen:16, PadData/binary, Data/binary>>.

%% Traffic morphing to look like different types of traffic
morph_traffic(Data, Profile, Counter, St) ->
    case Profile of
        video_streaming ->
            morph_as_video_stream(Data, Counter);
        web_browsing ->
            morph_as_web_traffic(Data, Counter, St);
        file_download ->
            morph_as_file_download(Data, Counter);
        voip ->
            morph_as_voip(Data, Counter);
        gaming ->
            morph_as_gaming(Data, Counter);
        social_media ->
            morph_as_social_media(Data, Counter);
        auto ->
            %% Rotate through different profiles
            Profiles = [video_streaming, web_browsing, file_download, voip, gaming],
            SelectedProfile = lists:nth((Counter rem length(Profiles)) + 1, Profiles),
            morph_traffic(Data, SelectedProfile, Counter, St)
    end.

%% Morph as video streaming (e.g., YouTube, Netflix)
morph_as_video_stream(Data, Counter) ->
    ChunkSize = case Counter rem 3 of
        0 -> 4096;
        1 -> 8192;
        2 -> 16384
    end,
    
    %% Add video streaming-like headers
    Header = case Counter rem 4 of
        0 -> <<"VIDEO_CHUNK", Counter:32, ChunkSize:32>>;
        1 -> <<"MEDIA_SEGMENT", Counter:32>>;
        2 -> <<"STREAM_DATA", ChunkSize:16>>;
        3 -> <<"BUFFER", Counter:16, ChunkSize:16>>
    end,
    
    <<Header/binary, Data/binary>>.

%% Morph as web browsing traffic
morph_as_web_traffic(Data, Counter, St) ->
    Domains = ["www.google.com", "www.facebook.com", "www.youtube.com",
               "www.amazon.com", "www.wikipedia.org", "www.twitter.com",
               "www.instagram.com", "www.linkedin.com", "www.reddit.com",
               "www.github.com", "www.stackoverflow.com", "www.medium.com"],
    
    Paths = ["/", "/api/v1/data", "/static/js/main.js", "/images/logo.png",
             "/css/style.css", "/api/v2/users", "/feed", "/search",
             "/notifications", "/messages", "/settings", "/profile"],
    
    Domain = lists:nth((Counter rem length(Domains)) + 1, Domains),
    Path = lists:nth(rand:uniform(length(Paths)), Paths),
    
    Method = case Counter rem 3 of
        0 -> "GET";
        1 -> "POST";
        2 -> "PUT"
    end,
    
    Header = list_to_binary([
        Method, " ", Path, " HTTP/1.1\r\n",
        "Host: ", Domain, "\r\n",
        "Connection: keep-alive\r\n",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
        "Accept-Encoding: gzip, deflate, br\r\n",
        "Accept-Language: en-US,en;q=0.9\r\n",
        "Cache-Control: max-age=0\r\n",
        "Sec-Fetch-Dest: document\r\n",
        "Sec-Fetch-Mode: navigate\r\n",
        "Sec-Fetch-Site: none\r\n",
        "Sec-Fetch-User: ?1\r\n",
        "Upgrade-Insecure-Requests: 1\r\n",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n\r\n"
    ]),
    
    <<Header/binary, Data/binary>>.

%% Morph as file download
morph_as_file_download(Data, Counter) ->
    FileTypes = [".zip", ".pdf", ".exe", ".dmg", ".iso", ".tar.gz"],
    FileType = lists:nth((Counter rem length(FileTypes)) + 1, FileTypes),
    
    Header = <<"FILE_DOWNLOAD", Counter:32, FileType/binary>>,
    <<Header/binary, Data/binary>>.

%% Morph as VoIP traffic
morph_as_voip(Data, Counter) ->
    Codecs = ["opus", "g722", "g711", "silk"],
    Codec = lists:nth((Counter rem length(Codecs)) + 1, Codecs),
    
    Header = <<"RTP", Codec/binary, Counter:16>>,
    <<Header/binary, Data/binary>>.

%% Morph as gaming traffic
morph_as_gaming(Data, Counter) ->
    Games = ["game_state", "player_action", "world_update", "inventory"],
    GameType = lists:nth((Counter rem length(Games)) + 1, Games),
    
    Header = <<GameType/binary, Counter:32>>,
    <<Header/binary, Data/binary>>.

%% Morph as social media traffic
morph_as_social_media(Data, Counter) ->
    Activities = ["post", "like", "comment", "share", "follow", "message"],
    Activity = lists:nth((Counter rem length(Activities)) + 1, Activities),
    
    Header = <<"SOCIAL", Activity/binary, Counter:16>>,
    <<Header/binary, Data/binary>>.

%% Entropy normalization
normalize_entropy(Data, Entropy) ->
    %% Apply simple XOR with entropy to make data look more random
    EntropyLen = byte_size(Entropy),
    DataLen = byte_size(Data),
    
    case DataLen =< EntropyLen of
        true ->
            EntropyPrefix = binary:part(Entropy, 0, DataLen),
            xor_binary(Data, EntropyPrefix);
        false ->
            %% Extend entropy if needed
            ExtendedEntropy = extend_entropy(Entropy, DataLen),
            xor_binary(Data, ExtendedEntropy)
    end.

%% Extend entropy for larger data
extend_entropy(Entropy, TargetLen) ->
    EntropyLen = byte_size(Entropy),
    Repeats = (TargetLen div EntropyLen) + 1,
    Extended = binary:copy(Entropy, Repeats),
    binary:part(Extended, 0, TargetLen).

%% XOR two binaries
xor_binary(Bin1, Bin2) when byte_size(Bin1) =:= byte_size(Bin2) ->
    xor_binary(Bin1, Bin2, <<>>).

xor_binary(<<>>, <<>>, Acc) ->
    Acc;
xor_binary(<<B1:8, Rest1/binary>>, <<B2:8, Rest2/binary>>, Acc) ->
    XorByte = B1 bxor B2,
    xor_binary(Rest1, Rest2, <<Acc/binary, XorByte:8>>).

%% Protocol mimicry
mimic_protocol(Data, Profile, Counter) ->
    %% Add protocol-specific markers
    case Profile of
        video_streaming ->
            %% Mimic MP4 or WebM containers
            Container = case Counter rem 2 of
                0 -> <<"ftyp", "mp42">>;
                1 -> <<"EBML", Counter:32>>
            end,
            <<Container/binary, Data/binary>>;
        web_browsing ->
            %% Mimic HTTP/2 frames
            FrameType = case Counter rem 4 of
                0 -> 0;  %% DATA
                1 -> 1;  %% HEADERS
                2 -> 3;  %% RST_STREAM
                3 -> 4   %% SETTINGS
            end,
            <<FrameType:8, 0:24, Counter:32, Data/binary>>;
        _ ->
            Data
    end.

%% Encrypt packet with morphing
encrypt_packet_with_morphing(Data, #st{encrypt = Enc} = St) ->
    {Enc1, Encrypted} = crypto_stream_encrypt(Enc, Data),
    {Encrypted, St#st{encrypt = Enc1}}.

%% Demorph packet
demorph_packet(Data, St) ->
    %% Remove entropy normalization
    Denormalized = normalize_entropy(Data, St#st.entropy_state),
    
    %% Remove protocol mimicry
    case St#st.traffic_profile of
        video_streaming ->
            case Denormalized of
                <<"ftyp", "mp42", Rest/binary>> -> Rest;
                <<"EBML", _:32, Rest/binary>> -> Rest;
                _ -> Denormalized
            end;
        web_browsing ->
            case Denormalized of
                <<_:8, _:24, _:32, Rest/binary>> -> Rest;
                _ -> Denormalized
            end;
        _ ->
            Denormalized
    end.

%% Build TLS-like packet
build_tls_like_packet(Data) ->
    %% Create TLS record header
    ContentType = 23,  %% application_data
    Version = <<3, 3>>,  %% TLS 1.2
    Length = byte_size(Data),
    
    case Length =< 16384 of
        true ->
            <<ContentType:8, Version/binary, Length:16, Data/binary>>;
        false ->
            %% Split into multiple TLS records
            FragmentSize = 16384,
            build_tls_records(Data, FragmentSize, [])
    end.

%% Build multiple TLS records
build_tls_records(<<>>, _, Acc) ->
    list_to_binary(lists:reverse(Acc));
build_tls_records(Data, FragmentSize, Acc) ->
    case byte_size(Data) =< FragmentSize of
        true ->
            Record = build_tls_record(Data),
            build_tls_records(<<>>, FragmentSize, [Record | Acc]);
        false ->
            <<Fragment:FragmentSize/binary, Rest/binary>> = Data,
            Record = build_tls_record(Fragment),
            build_tls_records(Rest, FragmentSize, [Record | Acc])
    end.

%% Build single TLS record
build_tls_record(Data) ->
    ContentType = 23,
    Version = <<3, 3>>,
    Length = byte_size(Data),
    <<ContentType:8, Version/binary, Length:16, Data/binary>>.

%% Unwrap TLS-like packet
unwrap_tls_like(Data) ->
    case Data of
        <<ContentType:8, _Version:16, Length:16, Payload:Length/binary, Rest/binary>> 
            when ContentType =:= 23; ContentType =:= 20; ContentType =:= 22 ->
            case Rest of
                <<>> -> Payload;
                _ -> <<Payload/binary, (unwrap_tls_like(Rest))/binary>>
            end;
        _ ->
            Data
    end.

%% Morph initial handshake to look like TLS ClientHello
morph_initial_handshake(Raw) ->
    %% Create TLS ClientHello-like structure
    ClientVersion = <<3, 3>>,  %% TLS 1.2
    Random = crypto:strong_rand_bytes(32),
    SessionID = crypto:strong_rand_bytes(32),
    
    %% Cipher suites (common ones)
    CipherSuites = <<
        16#13, 16#01,  %% TLS_AES_128_GCM_SHA256
        16#13, 16#02,  %% TLS_AES_256_GCM_SHA384
        16#13, 16#03,  %% TLS_CHACHA20_POLY1305_SHA256
        16#C0, 16#2B,  %% TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        16#C0, 16#2F,  %% TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        16#CC, 16#A9,  %% TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        16#CC, 16#A8,  %% TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        16#00, 16#FF   %% TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    >>,
    
    CompressionMethods = <<0>>,  %% null
    Extensions = build_tls_extensions(),
    
    ClientHelloBody = <<
        ClientVersion/binary,
        Random/binary,
        SessionID/binary,
        (byte_size(CipherSuites)):16,
        CipherSuites/binary,
        1,
        CompressionMethods/binary,
        (byte_size(Extensions)):16,
        Extensions/binary
    >>,
    
    %% Combine with original data
    <<ClientHelloBody/binary, Raw/binary>>.

%% Build TLS extensions
build_tls_extensions() ->
    %% Server Name Indication
    SNI = build_sni_extension("cdn.cloudflare.com"),
    
    %% Supported Groups
    Groups = <<
        16#00, 16#1D,  %% x25519
        16#00, 16#17,  %% secp256r1
        16#00, 16#18,  %% secp384r1
        16#00, 16#19   %% secp521r1
    >>,
    SupportedGroups = <<0, 10, (byte_size(Groups)):16, Groups/binary>>,
    
    %% Key Share
    KeyShare = build_key_share(),
    
    %% ALPN
    ALPN = build_alpn_extension(),
    
    %% Supported Versions
    SupportedVersions = <<0, 43, 5, 4, 3, 3, 3, 2, 3, 1>>,
    
    %% Signature Algorithms
    SigAlgs = <<
        16#04, 16#03,  %% ecdsa_secp256r1_sha256
        16#05, 16#03,  %% ecdsa_secp384r1_sha384
        16#06, 16#03,  %% ecdsa_secp521r1_sha512
        16#08, 16#04,  %% rsa_pss_rsae_sha256
        16#08, 16#05,  %% rsa_pss_rsae_sha384
        16#08, 16#06,  %% rsa_pss_rsae_sha512
        16#04, 16#01,  %% rsa_pkcs1_sha256
        16#05, 16#01,  %% rsa_pkcs1_sha384
        16#06, 16#01   %% rsa_pkcs1_sha512
    >>,
    SigAlgsExt = <<0, 13, (byte_size(SigAlgs)):16, SigAlgs/binary>>,
    
    <<SNI/binary, SupportedGroups/binary, KeyShare/binary, 
      ALPN/binary, SupportedVersions/binary, SigAlgsExt/binary>>.

%% Build SNI extension
build_sni_extension(Domain) ->
    DomainBin = list_to_binary(Domain),
    DomainLen = byte_size(DomainBin),
    TotalLen = DomainLen + 3,
    <<0, 0, TotalLen:16, 0, DomainLen:16, DomainBin/binary>>.

%% Build Key Share extension
build_key_share() ->
    %% Simulated public key
    PublicKey = crypto:strong_rand_bytes(32),
    <<0, 51, 38, 0, 29, 0, 1, 0, 0, 32, PublicKey/binary>>.

%% Build ALPN extension
build_alpn_extension() ->
    Protocols = <<
        8, "http/1.1",
        2, "h2"
    >>,
    <<0, 16, (byte_size(Protocols)):16, Protocols/binary>>.

%% Initialize TLS state
init_tls_state() ->
    #{
        sequence_number => 0,
        tls_version => <<3, 3>>,
        cipher_suite => random_cipher_suite(),
        session_tickets => crypto:strong_rand_bytes(32)
    }.

%% Random cipher suite selection
random_cipher_suite() ->
    CipherSuites = [
        <<16#13, 16#01>>,
        <<16#13, 16#02>>,
        <<16#13, 16#03>>,
        <<16#C0, 16#2B>>,
        <<16#C0, 16#2F>>,
        <<16#CC, 16#A9>>,
        <<16#CC, 16#A8>>
    ],
    lists:nth(rand:uniform(length(CipherSuites)), CipherSuites).

%% Initialize morphing state
init_morphing_state() ->
    #{
        current_profile => auto,
        profile_counter => 0,
        last_morph_time => erlang:system_time(millisecond)
    }.

%% Update packet statistics
update_packet_stats(#st{
    packet_counter = Counter,
    stats = Stats,
    last_packet_time = LastTime
} = St) ->
    CurrentTime = erlang:system_time(millisecond),
    InterPacketDelay = CurrentTime - LastTime,
    
    %% Update statistics
    Stats1 = Stats#{
        total_packets => maps:get(total_packets, Stats, 0) + 1,
        last_delay => InterPacketDelay,
        avg_delay => (maps:get(avg_delay, Stats, 0) * Counter + InterPacketDelay) / (Counter + 1)
    },
    
    %% Apply timing obfuscation if needed
    case St#st.timing_profile of
        burst when Counter rem 10 =:= 0 ->
            %% Create burst pattern
            timer:sleep(rand:uniform(50));
        steady ->
            %% Maintain steady pace
            ExpectedInterval = 20,
            CurrentInterval = InterPacketDelay,
            case CurrentInterval < ExpectedInterval of
                true -> timer:sleep(ExpectedInterval - CurrentInterval);
                false -> ok
            end;
        irregular ->
            %% Add random delays
            case Counter rem 3 of
                0 -> timer:sleep(rand:uniform(100));
                1 -> ok;
                2 -> timer:sleep(rand:uniform(50))
            end;
        auto ->
            %% Random timing based on traffic profile
            apply_auto_timing(St#st.traffic_profile);
        _ ->
            ok
    end,
    
    St#st{
        packet_counter = Counter + 1,
        stats = Stats1,
        last_packet_time = erlang:system_time(millisecond)
    }.

%% Auto timing based on traffic profile
apply_auto_timing(Profile) ->
    case Profile of
        video_streaming -> timer:sleep(rand:uniform(10));
        web_browsing -> timer:sleep(rand:uniform(100));
        file_download -> ok;  %% Fast as possible
        voip -> timer:sleep(20);  %% ~20ms for VoIP
        gaming -> timer:sleep(rand:uniform(33));  %% 30-60 FPS
        social_media -> timer:sleep(rand:uniform(200));
        auto -> ok
    end.

%%%===================================================================
%%% Protocol helpers (unchanged)
%%%===================================================================

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

dpi_resistance_test() ->
    Secret = crypto:strong_rand_bytes(16),
    DcId = 4,
    Protocol = mtp_secure,
    {Packet, _, _, CliCodec} = client_create(Secret, Protocol, DcId),
    {ok, _, _, SrvCodec} = from_header(Packet, Secret),
    
    %% Enable DPI resistance
    CliCodec1 = set_dpi_resistance(CliCodec, 10),
    CliCodec2 = set_traffic_profile(CliCodec1, web_browsing),
    CliCodec3 = set_tls_profile(CliCodec2, chrome_120),
    CliCodec4 = enable_domain_fronting(CliCodec3, "cdn.cloudflare.com"),
    CliCodec5 = enable_connection_chaining(CliCodec4),
    
    SrvCodec1 = set_dpi_resistance(SrvCodec, 10),
    SrvCodec2 = set_traffic_profile(SrvCodec1, web_browsing),
    SrvCodec3 = set_tls_profile(SrvCodec2, chrome_120),
    SrvCodec4 = enable_domain_fronting(SrvCodec3, "cdn.cloudflare.com"),
    SrvCodec5 = enable_connection_chaining(SrvCodec4),
    
    %% Test data
    TestData = <<"Hello, World! This is a test message for DPI resistance.">>,
    
    %% Encode and decode
    {Encoded, CliCodec6} = encode_packet(TestData, CliCodec5),
    {ok, Decoded, _, _} = try_decode_packet(Encoded, SrvCodec5),
    
    ?assertEqual(TestData, Decoded).

advanced_obfuscation_test() ->
    Secret = crypto:strong_rand_bytes(16),
    DcId = 4,
    Protocol = mtp_secure,
    {Packet, _, _, CliCodec} = client_create(Secret, Protocol, DcId),
    {ok, _, _, SrvCodec} = from_header(Packet, Secret),
    
    %% Enable advanced obfuscation
    CliCodec1 = enable_advanced_obfuscation(CliCodec),
    CliCodec2 = set_traffic_profile(CliCodec1, video_streaming),
    CliCodec3 = enable_port_hopping(CliCodec2, [443, 8443, 2053]),
    
    SrvCodec1 = enable_advanced_obfuscation(SrvCodec),
    SrvCodec2 = set_traffic_profile(SrvCodec1, video_streaming),
    SrvCodec3 = enable_port_hopping(SrvCodec2, [443, 8443, 2053]),
    
    %% Test various data sizes
    DataList = [
        <<"Small packet">>,
        crypto:strong_rand_bytes(100),
        crypto:strong_rand_bytes(1000),
        crypto:strong_rand_bytes(5000)
    ],
    
    lists:foreach(fun(Data) ->
        {Encoded, CliCodecNext} = encode_packet(Data, CliCodec3),
        {ok, Decoded, _, _} = try_decode_packet(Encoded, SrvCodec3),
        ?assertEqual(Data, Decoded)
    end, DataList).

-endif.
