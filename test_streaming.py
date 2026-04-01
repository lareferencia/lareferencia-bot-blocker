import os
import logging
import ipaddress
from datetime import datetime, timezone
from parser import stream_log_entries
from threat_analyzer import ThreatAnalyzer

# Setup basic logging
logging.basicConfig(level=logging.INFO)

def create_dummy_log(filename):
    entries = [
        '192.168.1.1 - - [22/Nov/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla"',
        '192.168.1.1 - - [22/Nov/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla"',
        '192.168.1.2 - - [22/Nov/2025:10:00:02 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla"',
        '10.0.0.1 - - [22/Nov/2025:10:00:03 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla"'
    ]
    with open(filename, 'w') as f:
        for e in entries:
            f.write(e + '\n')
    return len(entries)


def create_concatenated_log(filename):
    entries = [
        '192.168.1.1 - - [22/Nov/2025:10:00:00 +0000] "GET /a HTTP/1.1" 200 123 "-" "Mozilla"',
        '192.168.1.2 - - [22/Nov/2025:10:00:01 +0000] "GET /b HTTP/1.1" 200 123 "-" "Mozilla"',
        '10.0.0.1 - - [22/Nov/2025:10:00:02 +0000] "GET /c HTTP/1.1" 200 123 "-" "Mozilla"',
        '10.0.0.2 - - [22/Nov/2025:10:00:03 +0000] "GET /d HTTP/1.1" 200 123 "-" "Mozilla"'
    ]
    with open(filename, 'w') as f:
        f.write(entries[0] + entries[1] + '\n')
        f.write(entries[2] + entries[3] + '\n')
    return len(entries)


def create_short_format_log(filename):
    entries = [
        '192.168.1.1 - - [22/Nov/2025:10:00:00 +0000] "GET /a HTTP/1.1" 200 123',
        '192.168.1.1 - - [22/Nov/2025:10:00:01 +0000] "GET /b HTTP/1.1" 200 123',
        '10.0.0.1 - - [22/Nov/2025:10:00:02 +0000] "GET /c HTTP/1.1" 404 0',
    ]
    with open(filename, 'w') as f:
        for e in entries:
            f.write(e + '\n')
    return len(entries)


def create_mixed_format_log(filename):
    full_a = '192.168.1.1 - - [22/Nov/2025:10:00:00 +0000] "GET /a HTTP/1.1" 200 123 "-" "Mozilla"'
    short_b = '192.168.1.2 - - [22/Nov/2025:10:00:01 +0000] "GET /b HTTP/1.1" 200 123'
    malformed_partial = '45.232.32.91 - - [22/No'
    full_c = '10.0.0.1 - - [22/Nov/2025:10:00:02 +0000] "GET /c HTTP/1.1" 200 123 "-" "Mozilla"'
    short_d = '10.0.0.2 - - [22/Nov/2025:10:00:03 +0000] "GET /d HTTP/1.1" 200 123'

    with open(filename, 'w') as f:
        f.write(full_a + short_b + '\n')
        f.write(malformed_partial + full_c + short_d + '\n')

    return 4


def create_real_world_full_format_log(filename):
    entries = [
        '6.248.200.214 - - [01/Apr/2026:12:09:55 +0000] "GET /vufind/Record/PE_73a8e3f6f238ec2698a6b8a981990749/Description HTTP/1.1" 200 41228 "https://www.lareferencia.info/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15"',
        '216.209.199.44 - - [01/Apr/2026:12:09:56 +0000] "GET /vufind/Record/CL_fdd1f47eb9f310f0308e2815fcb1d003?lng=ja HTTP/1.1" 404 23265 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:132.0) Gecko/20100101 Firefox/132.0"',
        '103.157.88.93 - - [01/Apr/2026:12:09:55 +0000] "GET /vufind/Record/BR_f35728c257c1f84d19657d76cff5127f/Description?lng=nl HTTP/1.1" 200 39115 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.116 Safari/537.36"',
        '113.181.6.166 - - [01/Apr/2026:12:09:55 +0000] "GET /vufind/Record/AR_6ca9417f4b5718787e11b6c27763e799?lng=es HTTP/1.1" 200 40481 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.84 Safari/537.36"',
        '187.188.155.201 - - [01/Apr/2026:12:09:56 +0000] "GET /vufind/Record/MX_11674047c2dac9ca1a22cab008bda4e6/Details?lng=ja HTTP/1.1" 200 50633 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:127.0) Gecko/20100101 Firefox/127.0"',
        '113.188.158.215 - - [01/Apr/2026:12:09:55 +0000] "GET /vufind/Record/MX_5d8c18d40fa4c0b43a2c7e61f4d3814a/Details?lng=de HTTP/1.1" 200 50405 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Safari/537.36"',
        '167.0.120.35 - - [01/Apr/2026:12:09:56 +0000] "GET /vufind/Record/ES_9278234457986e3f89ac85276b4c8017/Cite?lng=ja HTTP/2.0" 200 24791 "-" "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.4248.1772 Mobile Safari/537.36"',
        '58.164.67.66 - - [01/Apr/2026:12:09:57 +0000] "GET /vufind/Record/ES_3eef694cd6964e51e3a304bf53e3104b/Export?style=EndNoteWeb HTTP/2.0" 302 - "-" "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.7385.1070 Mobile Safari/537.36"',
        '14.179.59.18 - - [01/Apr/2026:12:09:56 +0000] "GET /vufind/Record/BR_e8019ad12252461f8603fde5eb1bc162/Description?lng=nl HTTP/1.1" 200 35362 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.155 Safari/537.36"',
        '105.101.143.205 - - [01/Apr/2026:12:09:56 +0000] "GET /vufind/Record/ES_0af80407798df8aa2ec1a71dcb737ced/Details?lng=ca HTTP/1.1" 200 51803 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0"',
        '201.110.109.11 - - [01/Apr/2026:12:09:56 +0000] "GET /vufind/Record/ES_8416263041e2c18adf16ec5947294ce1/Description HTTP/1.1" 200 44595 "https://lareferencia.info/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"',
        '67.167.114.180 - - [01/Apr/2026:12:09:56 +0000] "GET /vufind/Record/BR_addda3b49e64ec5503f1c2ade94ffa70/Details?lng=fr HTTP/1.1" 200 58248 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 12.1; rv:125.0) Gecko/20100101 Firefox/125.0"',
        '154.161.109.30 - - [01/Apr/2026:12:09:56 +0000] "GET /vufind/Record/PE_286164a9bc1aa28169ee84b06d1e47c5/Details?lng=fi HTTP/1.1" 200 56232 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.58 Safari/537.36"',
        '159.192.64.118 - - [01/Apr/2026:12:09:56 +0000] "GET /vufind/Record/MX_d1102ab67f241e12c00528e3d81465dc/Description?lng=pt HTTP/1.1" 200 36600 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.120 Safari/537.36"',
        '190.181.84.221 - - [01/Apr/2026:12:09:55 +0000] "GET /vufind/Record/BR_fe94b7bc7d1556018674abc8ffed67c1/OpenAIRE?lng=sl HTTP/1.1" 500 20158 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.141 Safari/537.36"',
        '120.28.219.132 - - [01/Apr/2026:12:09:56 +0000] "GET /vufind/Record/PE_462dc66fccef308d11de7ed7d17826c8?lng=cs HTTP/1.1" 200 37171 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 12.7; rv:131.0) Gecko/20100101 Firefox/131.0"',
    ]
    with open(filename, 'w') as f:
        for e in entries:
            f.write(e + '\n')
    return len(entries)


def create_real_world_short_format_log(filename):
    lines = [
        '113.177.168.244 - - [26/Mar/2026:16:05:39 -0300] "GET /vufind/Record/UEL-8_92ef67392a3b0f735c1618489aec5d54/Details HTTP/1.1" 200 5914',
        '109.228.196.195 - - [26/Mar/2026:16:05:39 -0300] "GET /vufind/Record/CRUZ_ae60dd6d6c086cb69c30c7abdcd6f396/Details?lng=en HTTP/1.1" 200 5914',
        '123.27.91.117 - - [26/Mar/2026:16:05:39 -0300] "GET /vufind/Search/Advanced?edit=37386872 HTTP/1.1" 200 5914',
        '170.245.94.212 - - [26/Mar/2026:16:05:39 -0300] "GET /vufind/themes/oasisbr/images/footeratualizado.png?_=1761139737 HTTP/2.0" 200 59952',
        '170.245.94.212 - - [26/Mar/2026:16:05:39 -0300] "GET /vufind/themes/oasisbr/images/footeratualizado-responsiva.png?_=1761139737 HTTP/2.0" 200 97443',
        '170.245.94.212 - - [26/Mar/2026:16:05:39 -0300] "GET /vufind/themes/bootstrap3/css/print.css HTTP/2.0" 200 260',
        '170.245.94.212 - - [26/Mar/2026:16:05:40 -0300] "GET /vufind/themes/bootstrap3/css/fonts/fontawesome-webfont.woff2?v=4.7.0 HTTP/2.0" 200 77287',
        '17.241.75.93 - - [26/Mar/2026:16:05:40 -0300] "GET /vufind/Author/Home?author=Concei%C3%A7%C3%A3o%2C+D%C3%A9bora+K%C3%A9len+Silva+da HTTP/1.1" 403 5210',
        '66.249.73.2 - - [26/Mar/2026:16:05:39 -0300] "GET /vufind/Author/Home?author=Reis%2CEdna+Afonso HTTP/1.1" 200 12894',
        '193.186.4.202 - - [26/Mar/2026:16:05:40 -0300] "GET /vufind/Record/UFSC_50a766c16015ce6523a796f4f7378ce0 HTTP/2.0" 200 1007',
        '45.166.205.190 - - [26/Mar/2026:16:05:40 -0300] "GET /vufind/Record/ABORL-F-1_a62d5d508f0f3fb0e498d0ae6ff240b1/Details HTTP/1.1" 200 5914',
        '173.72.172.178 - - [26/Mar/2026:16:05:40 -0300] "GET /vufind/Record/UEL-8_c3e57b0a05740637e04242a60120ee24/Details HTTP/1.1" 200 5914',
        '113.173.91.218 - - [26/Mar/2026:16:05:41 -0300] "GET /vufind/Search/Results?lookfor=%28%28%222010+fifa+world+s+qualification%22%29+OR+%28%222014+fifa+world+service+qualification%22%29%29%2A HTTP/1.1" 200 5914',
        '17.241.75.57 - - [26/Mar/2026:16:05:41 -0300] "GET /vufind/Author/Home?author=Nunes%2C+Nat%C3%A1lia+Paz HTTP/1.1" 403 5210',
        '69.124.98.120 - - [26/Mar/2026:16:05:41 -0300] "GET /vufind/Record/UEL-8_f8720916ba1c83b1f7f3766a993f1c9f/Details?lng=pt-br HTTP/1.1" 200 5914',
        '‎Leer más',
    ]
    with open(filename, 'w') as f:
        for line in lines:
            f.write(line + '\n')
    return 15


def create_real_world_long_request_log(filename):
    lines = [
        '70.79.203.148 - - [26/Mar/2026:16:06:15 -0300] "GET /vufind/Search/Results?lookfor=%28%28%28%28%28%22treinadosr%22+OR+%28%22treinadossr%22+OR+%28%22treinadorar%22+OR+%22treinadoras%22%29%29%29+OR+%28%22treinadossr%22+OR+%28%22treinadorar%22+OR+%22treinadoras%22%29%29%29+OR+%28%22treinadoress%22+OR+%22tresinadoress%22%29%29+OR+%22treinado%22%29+OR+%28%28%22treinadoses%22+OR+%28%28%28%22treinadores%22+OR+%22tresinadores%22%29+OR+%28%28%22treinadosreste%22+OR+%22treinadoresel%22%29+OR+%22treinadoresde%22%29%29+OR+%22treinadoses%22%29%29+OR+%28%28%22treinada%22+OR+%28%28%28%28%28%22treinadoss%22+OR+%22treinadora%22%29+OR+%22treinadas%22%29+OR+%28%22treinadoso%22+OR+%22treinandos%22%29%29+OR+%22treinador%22%29+OR+%22treinadosra%22%29%29+OR+%28%22ostresinadores%22+OR+%28%28%22reinadores%22+OR+%22refinadores%22%29+OR+%28%22treinadossssres%22+OR+%22treinadosssssres%22%29%29%29%29%29%29&page=5&type=AllFields HTTP/1.1" 200 1149 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"',
        '45.225.224.100 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/Record/UESB-2_a5f0459922fa3606072e1104669fbb01/Details HTTP/1.1" 200 1150 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.55 Safari/537.36"',
        '45.238.237.49 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/Record/BRCRIS_3d976c813a61355f8090ec3082d6758e HTTP/1.1" 200 8538 "https://www.oasisbr.ibict.br/vufind/Record/BRCRIS_3d976c813a61355f8090ec3082d6758e" "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"',
        '17.246.15.148 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/Author/Home?author=Machado%2C+Adriana+Alexandria HTTP/1.1" 403 497 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)"',
        '45.238.237.49 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/themes/oasisbr/images/youtube.png?_=1714395043 HTTP/1.1" 200 1720 "https://www.oasisbr.ibict.br/vufind/Record/BRCRIS_3d976c813a61355f8090ec3082d6758e" "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"',
        '45.238.237.49 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/themes/oasisbr/images/logoibictversao1.png?_=1761139737 HTTP/1.1" 200 232351 "https://www.oasisbr.ibict.br/vufind/Record/BRCRIS_3d976c813a61355f8090ec3082d6758e" "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"',
        '66.249.73.2 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/Record/SBMV-1_8263b36ba39b8a9096c33098c511e963/Details?lng=en HTTP/1.1" 200 11336 "-" "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.153 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"',
        '191.99.52.233 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/Record/UESB-2_ef77e4cf818e63f46f1d0ba965dd9128/Details?lng=pt-br HTTP/1.1" 200 1149 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.45 Safari/537.36"',
        '45.238.237.49 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/themes/oasisbr/images/facebook.png?_=1714395043 HTTP/1.1" 200 1639 "https://www.oasisbr.ibict.br/vufind/Record/BRCRIS_3d976c813a61355f8090ec3082d6758e" "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"',
        '45.238.237.49 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/themes/oasisbr/images/twitter.png?_=1714395043 HTTP/1.1" 200 1928 "https://www.oasisbr.ibict.br/vufind/Record/BRCRIS_3d976c813a61355f8090ec3082d6758e" "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"',
        '186.14.200.143 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/Search/Results?lookfor=%28%28%28%22treinadosr%22+OR+%22treinadosras%22%29+OR+%22treinado%22%29+OR+%28%28%28%28%28%22treinadosrs%22+OR+%22treinandoss%22%29+OR+%22treinados%22%29+OR+%22treinadoso%22%29+OR+%28%22treinadoresacute%22+OR+%28%22treinadoseste%22+OR+%28%28%28%28%28%22tetreinadores%22+OR+%22determinadores%22%29+OR+%22detreinadores%22%29+OR+%28%22dtreinadores%22+OR+%28%22treinadores%22+OR+%22treinadoses%22%29%29%29+OR+%22tetruminadores%22%29+OR+%28%22etreinadores%22+OR+%22etrefinadores%22%29%29%29%29%29+OR+%28%28%22treinada%22+OR+%28%28%22treinadoss%22+OR+%22treinadas%22%29+OR+%28%22treinadora%22+OR+%22treinadosra%22%29%29%29+OR+%28%28%28%28%22ostreinados%22+OR+%22ostrefinadores%22%29+OR+%22ostreinadoses%22%29+OR+%22ostreinados%22%29+OR+%28%28%22reinadores%22+OR+%22resinadores%22%29+OR+%28%22treinadossssres%22+OR+%28%28%22treinadorasssssres%22+OR+%22treinadosasssssres%22%29+OR+%22treinadossssres%22%29%29%29%29%29%29%29&page=8&type=AllFields HTTP/1.1" 200 1149 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"',
        '45.238.237.49 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/themes/oasisbr/images/linkedin.svg?_=1714395043 HTTP/1.1" 200 1228 "https://www.oasisbr.ibict.br/vufind/Record/BRCRIS_3d976c813a61355f8090ec3082d6758e" "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"',
        '45.238.237.49 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/themes/bootstrap3/css/fonts/fontawesome-webfont.woff2?v=4.7.0 HTTP/1.1" 200 77449 "https://www.oasisbr.ibict.br/vufind/cache/be5aaaa68da4c8f80e9b21af69c0a2c4.min.css" "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"',
        '45.238.237.49 - - [26/Mar/2026:16:06:16 -0300] "GET /vufind/themes/oasisbr/images/footeratualizado.png?_=1761139737 HTTP/1.1" 200 60153 "https://www.oasisbr.ibict.br/vufind/Record/BRCRIS_3d976c813a61355f8090ec3082d6758e" "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (',
    ]
    with open(filename, 'w') as f:
        for line in lines:
            f.write(line + '\n')
    return 14

def test_streaming_analysis():
    log_file = "test_dummy.log"
    create_dummy_log(log_file)
    
    print(f"Created dummy log: {log_file}")
    
    analyzer = ThreatAnalyzer()
    
    print("Running analyze_log_file...")
    count = analyzer.analyze_log_file(log_file)
    
    print(f"Processed count: {count}")
    
    if count != 4:
        print("FAIL: Expected 4 entries processed.")
        return

    # Check IP metrics
    ip_metrics = analyzer.ip_metrics
    print(f"IP Metrics keys: {list(ip_metrics.keys())}")
    
    if '192.168.1.1' not in ip_metrics:
        print("FAIL: 192.168.1.1 not found in metrics.")
        return
        
    if ip_metrics['192.168.1.1']['total_requests'] != 2:
        print(f"FAIL: Expected 2 requests for 192.168.1.1, got {ip_metrics['192.168.1.1']['total_requests']}")
        return

    print("IP Metrics verification passed.")

    # Check Identify Threats
    print("Running identify_threats...")
    # Mock config
    class Config:
        min_rpm_threshold = 10
        min_sustained_percent = 20
        max_cpu_load_threshold = 80
    
    shared_context = {'analysis_duration_seconds': 60}
    
    threats = analyzer.identify_threats(
        strategy_name='unified',
        shared_context_params=shared_context,
        config=Config()
    )
    
    if threats is not None:
        print(f"Threats identified: {len(threats)}")
        single_ip_threat = None
        for threat in threats:
            if threat['id'] == ipaddress.ip_network("10.0.0.0/24"):
                single_ip_threat = threat
                break
        if single_ip_threat is None:
            print("FAIL: Expected threat for 10.0.0.0/24 not found.")
            return
        if single_ip_threat.get('single_ip') != '10.0.0.1':
            print(f"FAIL: Expected single_ip=10.0.0.1, got {single_ip_threat.get('single_ip')}")
            return
        print("Identify Threats verification passed.")
    else:
        print("FAIL: identify_threats returned None")

    # Cleanup
    os.remove(log_file)
    print("Test completed successfully.")


def test_streaming_analysis_with_concatenated_lines():
    log_file = "test_concatenated.log"
    create_concatenated_log(log_file)

    analyzer = ThreatAnalyzer()
    count = analyzer.analyze_log_file(log_file)
    if count != 4:
        print(f"FAIL: Expected 4 concatenated entries processed, got {count}")
        return

    start_date_utc = datetime(2025, 11, 22, 10, 0, 2, tzinfo=timezone.utc)
    analyzer_recent = ThreatAnalyzer()
    recent_count = analyzer_recent.analyze_log_file(log_file, start_date_utc=start_date_utc)
    if recent_count != 2:
        print(f"FAIL: Expected 2 recent concatenated entries processed, got {recent_count}")
        return

    os.remove(log_file)
    print("Concatenated line parsing verification passed.")


def test_streaming_analysis_with_short_lines():
    log_file = "test_short.log"
    create_short_format_log(log_file)

    entries = list(stream_log_entries(log_file))
    if len(entries) != 3:
        print(f"FAIL: Expected 3 short-format entries processed, got {len(entries)}")
        return
    if sorted(entries[0].keys()) != ['ip', 'timestamp']:
        print(f"FAIL: Expected parser output keys ['ip', 'timestamp'], got {sorted(entries[0].keys())}")
        return

    analyzer = ThreatAnalyzer()
    count = analyzer.analyze_log_file(log_file)
    if count != 3:
        print(f"FAIL: Expected 3 short-format entries analyzed, got {count}")
        return
    if analyzer.ip_metrics['192.168.1.1']['total_requests'] != 2:
        print("FAIL: Short-format metrics changed unexpectedly.")
        return

    os.remove(log_file)
    print("Short-format parsing verification passed.")


def test_streaming_analysis_with_mixed_concatenated_lines():
    log_file = "test_mixed.log"
    create_mixed_format_log(log_file)

    entries = list(stream_log_entries(log_file))
    if len(entries) != 4:
        print(f"FAIL: Expected 4 mixed-format entries processed, got {len(entries)}")
        return
    if sorted(entries[0].keys()) != ['ip', 'timestamp']:
        print(f"FAIL: Expected parser output keys ['ip', 'timestamp'], got {sorted(entries[0].keys())}")
        return

    analyzer = ThreatAnalyzer()
    count = analyzer.analyze_log_file(log_file)
    if count != 4:
        print(f"FAIL: Expected 4 mixed-format entries analyzed, got {count}")
        return

    start_date_utc = datetime(2025, 11, 22, 10, 0, 2, tzinfo=timezone.utc)
    analyzer_recent = ThreatAnalyzer()
    recent_count = analyzer_recent.analyze_log_file(log_file, start_date_utc=start_date_utc)
    if recent_count != 2:
        print(f"FAIL: Expected 2 recent mixed-format entries processed, got {recent_count}")
        return

    os.remove(log_file)
    print("Mixed-format concatenated parsing verification passed.")


def test_streaming_analysis_with_real_world_full_format_lines():
    log_file = "test_real_world_full.log"
    expected_count = create_real_world_full_format_log(log_file)

    entries = list(stream_log_entries(log_file))
    if len(entries) != expected_count:
        print(f"FAIL: Expected {expected_count} real-world full-format entries processed, got {len(entries)}")
        return
    if entries[0]['ip'] != '6.248.200.214':
        print(f"FAIL: Unexpected first IP for full-format sample: {entries[0]['ip']}")
        return
    if entries[-1]['ip'] != '120.28.219.132':
        print(f"FAIL: Unexpected last IP for full-format sample: {entries[-1]['ip']}")
        return

    analyzer = ThreatAnalyzer()
    count = analyzer.analyze_log_file(log_file)
    if count != expected_count:
        print(f"FAIL: Expected {expected_count} full-format entries analyzed, got {count}")
        return

    os.remove(log_file)
    print("Real-world full-format parsing verification passed.")


def test_streaming_analysis_with_real_world_short_format_lines():
    log_file = "test_real_world_short.log"
    expected_count = create_real_world_short_format_log(log_file)

    entries = list(stream_log_entries(log_file))
    if len(entries) != expected_count:
        print(f"FAIL: Expected {expected_count} real-world short-format entries processed, got {len(entries)}")
        return
    if entries[0]['timestamp'].isoformat() != '2026-03-26T19:05:39+00:00':
        print(f"FAIL: Unexpected UTC conversion for short-format sample: {entries[0]['timestamp'].isoformat()}")
        return
    if entries[-1]['ip'] != '69.124.98.120':
        print(f"FAIL: Unexpected last IP for short-format sample: {entries[-1]['ip']}")
        return

    analyzer = ThreatAnalyzer()
    count = analyzer.analyze_log_file(log_file)
    if count != expected_count:
        print(f"FAIL: Expected {expected_count} short-format entries analyzed, got {count}")
        return
    if analyzer.ip_metrics['170.245.94.212']['total_requests'] != 4:
        print("FAIL: Expected 4 requests for 170.245.94.212 in short-format sample.")
        return

    os.remove(log_file)
    print("Real-world short-format parsing verification passed.")


def test_streaming_analysis_with_real_world_long_request_lines():
    log_file = "test_real_world_long.log"
    expected_count = create_real_world_long_request_log(log_file)

    entries = list(stream_log_entries(log_file))
    if len(entries) != expected_count:
        print(f"FAIL: Expected {expected_count} real-world long-request entries processed, got {len(entries)}")
        return
    if entries[0]['ip'] != '70.79.203.148':
        print(f"FAIL: Unexpected first IP for long-request sample: {entries[0]['ip']}")
        return
    if entries[-1]['ip'] != '45.238.237.49':
        print(f"FAIL: Unexpected last IP for long-request sample: {entries[-1]['ip']}")
        return

    analyzer = ThreatAnalyzer()
    count = analyzer.analyze_log_file(log_file)
    if count != expected_count:
        print(f"FAIL: Expected {expected_count} long-request entries analyzed, got {count}")
        return
    if analyzer.ip_metrics['45.238.237.49']['total_requests'] != 8:
        print("FAIL: Expected 8 requests for 45.238.237.49 in long-request sample.")
        return

    os.remove(log_file)
    print("Real-world long-request parsing verification passed.")

if __name__ == "__main__":
    test_streaming_analysis()
    test_streaming_analysis_with_concatenated_lines()
    test_streaming_analysis_with_short_lines()
    test_streaming_analysis_with_mixed_concatenated_lines()
    test_streaming_analysis_with_real_world_full_format_lines()
    test_streaming_analysis_with_real_world_short_format_lines()
    test_streaming_analysis_with_real_world_long_request_lines()
