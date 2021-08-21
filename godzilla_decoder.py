#!/usr/bin/env python3
"""
project: https://github.com/think3t/godzilla_decoder
author:  think3t
usage:
  mitmweb -s godzilla_decoder.py [-p 9090] [--set pas=SHELL_PASS] [--set key=SHELL_KEY] [--set charset=gb2312]
  optional arguments:
    --set help              show this help message and exit
    -p PORT, --listen-port PORT
                            mitmproxy listening port, default: 8080
    --set pas=SHELL_PASS    shell password, default: pass
    --set key=SHELL_KEY     shell key, default: key
    --set charset=gb2312    shell charset, default: utf-8

examples:
  mitmweb -s godzilla_decoder.py
  mitmweb -s godzilla_decoder.py -p 9090 --set pas=test --set key=shell_key --set charset=gb2312
"""


import io
import sys
import gzip
import base64
import struct
import typing
import hashlib
from urllib import parse
import mitmproxy.http
from mitmproxy import ctx


def gen_key(key):
    key_md5 = hashlib.md5(key.encode("utf-8")).hexdigest()
    return key_md5[:16]


def gen_find_str(pas='pass', key='key', encoding='utf-8', shell_type='PHP_XOR_BASE64'):
    if shell_type == 'PHP_XOR_BASE64':
        secret_key = gen_key(key)
        find_str = hashlib.md5('{}{}'.format(
            pas, secret_key).encode(encoding)).hexdigest()
        return find_str[:16]
    if shell_type == 'PHP_EVAL_XOR_BASE64':
        secret_key = gen_key(key)
        find_str = hashlib.md5('{}{}'.format(
            key, secret_key).encode(encoding)).hexdigest()
        return find_str[:16]


def decode(str_data, key, is_request=True):
    if is_request:  # 对于请求数据先进行URL解码
        str_data = parse.unquote(str_data)
    cs = base64.b64decode(str_data)
    result = []
    for i in range(len(cs)):
        result.append(cs[i] ^ ord(key[i + 1 & 15]))
    return struct.pack('B'*len(result), *result)


def decode_raw(bytes_data, key):
    cs = bytes_data
    result = []
    for i in range(len(cs)):
        result.append(cs[i] ^ ord(key[i + 1 & 15]))
    return struct.pack('B'*len(result), *result)


def gzip_decompress(byte_data):
    if len(byte_data) == 0:
        return byte_data
    else:
        try:
            result = gzip.decompress(byte_data)
        except OSError:
            result = byte_data
    return result


def gzip_decompress2(byte_data):
    if len(byte_data) == 0:
        return byte_data
    else:
        obj = io.BytesIO(byte_data)
        with gzip.GzipFile(fileobj=obj) as f:
            result = f.read()
        return result


def format_parameter(pms, encoding="utf-8"):
    parameter = {}
    index = 0
    key_bytes = []

    while True:
        q = pms[index]
        if q == 0x02:
            length = int.from_bytes(
                pms[index+1:index+5], byteorder=sys.byteorder)
            index += 4
            value = pms[index+1:index+length+1].decode(encoding)
            key = struct.pack('B'*len(key_bytes), *key_bytes).decode(encoding)
            parameter[key] = value
            index += length
            key_bytes = []
        else:
            key_bytes.append(q)
        index += 1
        if index > len(pms) - 1:
            break
    return parameter


def parse_request(request_data, key, init_req=False, encoding="utf-8"):
    if init_req:
        return gzip_decompress(decode(request_data, key, True)).decode("utf-8")
    else:
        return format_parameter(gzip_decompress(decode(request_data, key)), encoding)


def parse_request_raw(request_data, key, init_req=False, encoding="utf-8"):
    if init_req:
        return gzip_decompress(decode_raw(request_data, key)).decode("utf-8")
    else:
        return format_parameter(gzip_decompress(decode_raw(request_data, key)), encoding)


def parse_eval_content(eval_content):
    content = parse.unquote(eval_content)
    content = ''.join(reversed(content))
    content = base64.b64decode(bytes(content, encoding="utf-8"))
    return str(content, encoding="utf-8")


def parse_response(response_data, key, encoding="utf-8"):
    data_length = len(response_data)
    valid_resp_data = response_data[16:data_length-16]  # 去掉响应包首尾分别追加的16字节内容
    return gzip_decompress(decode(valid_resp_data, key, False)).decode(encoding)


def parse_response_raw(response_data, key, encoding="utf-8"):
    return gzip_decompress(decode_raw(response_data, key)).decode(encoding)


class GodZilla:
    def __init__(self):
        self.shell_type = 'PHP_XOR_BASE64'
        ctx.log.info("""
********************** script help message **********************
project: https://github.com/think3t/godzilla_decoder
author:  think3t
usage:
  mitmweb -s godzilla_decoder.py [-p 9090] [--set pas=SHELL_PASS] [--set key=SHELL_KEY] [--set charset=gb2312]
  optional arguments:
    --set help              show this help message and exit
    -p PORT, --listen-port PORT
                            mitmproxy listening port, default: 8080
    --set pas=SHELL_PASS    shell password, default: pass
    --set key=SHELL_KEY     shell key, default: key
    --set charset=gb2312    shell charset, default: utf-8

examples:
  mitmweb -s godzilla_decoder.py
  mitmweb -s godzilla_decoder.py -p 9090 --set pas=test --set key=shell_key --set charset=gb2312
********************** script help message **********************

""")

    def load(self, loader):
        loader.add_option(
            name="pas",
            typespec=typing.Optional[str],
            default="pass",
            help="shell password, default: pass"
        )

        loader.add_option(
            name="key",
            typespec=typing.Optional[str],
            default="key",
            help="shell key, default: key"
        )

        loader.add_option(
            name="charset",
            typespec=typing.Optional[str],
            default="utf-8",
            help="shell charset, default: utf-8"
        )

    def request(self, flow: mitmproxy.http.HTTPFlow):
        # 初始连接请求头中无Cookie字段
        if 'Cookie' not in flow.request.headers:
            init_req = True
        else:
            init_req = False
        try:
            content = flow.request.content.decode(ctx.options.charset)
            if "{}=".format(ctx.options.pas) in content:
                if "{}=".format(ctx.options.key) in content:  # PHP_EVAL_XOR_BASE64
                    self.shell_type = 'PHP_EVAL_XOR_BASE64'
                    ctx.log.info("Detect shell type: PHP_EVAL_XOR_BASE64")
                    params = content.split('&')
                    pass_key, pass_value = params[0].split('=')
                    key_key, key_value = params[1].split('=')
                    php_eval, eval_content, end_content = parse.unquote(
                        pass_value).split("'")
                    decoded_eval_content = parse_eval_content(eval_content)
                    decoded_key_value = parse_request(
                        key_value, gen_key(ctx.options.key), init_req, ctx.options.charset)
                    ctx.log.info("-" * 64)
                    ctx.log.info("Decoded request content is:")
                    ctx.log.info(
                        "++++++++ BEGIN OF POST PARAMETER [{}] {}".format(pass_key, '+'*(28-len(pass_key))))
                    ctx.log.info("{}'[SOME_ENCODED_DATA]'{}".format(
                        php_eval, end_content))
                    ctx.log.info("+" * 32)
                    ctx.log.info(
                        "[SOME_ENCODED_DATA] can be decoded as below: ")
                    ctx.log.info(decoded_eval_content)
                    ctx.log.info(
                        "++++++++ END OF POST PARAMETER [{}] {}\n".format(pass_key, '+'*(30-len(pass_key))))
                    ctx.log.info("++++++++ BEGIN OF POST PARAMETER [{}] {}\n{}".format(
                        key_key, '+'*(28-len(key_key)), decoded_key_value))
                    ctx.log.info(
                        "++++++++ END OF POST PARAMETER [{}] {}\n".format(key_key, '+'*(30-len(key_key))))
                    ctx.log.info("-" * 64)
                else:  # PHP_XOR_BASE64
                    self.shell_type = 'PHP_XOR_BASE64'
                    ctx.log.info("Detect shell type: PHP_XOR_BASE64")
                    param_key, param_value = content.split('=')
                    content_decoded = parse_request(
                        param_value, gen_key(ctx.options.key), init_req, ctx.options.charset)
                    ctx.log.info("-" * 64)
                    ctx.log.info("Decoded request content is: \n{}={}".format(
                        param_key, content_decoded))
                    ctx.log.info("-" * 64)
            else:  # PHP_XOR_RAW
                self.shell_type = 'PHP_XOR_RAW'
                ctx.log.info("Detect shell type: PHP_XOR_RAW")
                content = flow.request.content
                content_decoded = parse_request_raw(content, gen_key(
                    ctx.options.key), init_req, ctx.options.charset)
                ctx.log.info("-" * 64)
                ctx.log.info(
                    "Decoded request content is: \n{}".format(content_decoded))
                ctx.log.info("-" * 64)
        except UnicodeDecodeError:  # PHP_XOR_RAW
            content = flow.request.content
            self.shell_type = 'PHP_XOR_RAW'
            ctx.log.info("Detect shell type: PHP_XOR_RAW")
            content = flow.request.content
            content_decoded = parse_request_raw(content, gen_key(
                ctx.options.key), init_req, ctx.options.charset)
            ctx.log.info("-" * 64)
            ctx.log.info(
                "Decoded request content is: \n{}".format(content_decoded))
            ctx.log.info("-" * 64)

    def response(self, flow: mitmproxy.http.HTTPFlow):
        content_length = int(flow.request.headers['Content-Length'])
        if content_length > 0:
            content = flow.response.content
            find_str_1 = gen_find_str(
                ctx.options.pas, ctx.options.key, ctx.options.charset, 'PHP_XOR_BASE64')
            find_str_2 = gen_find_str(
                ctx.options.pas, ctx.options.key, ctx.options.charset, 'PHP_EVAL_XOR_BASE64')

            if find_str_1.encode('utf-8') in content or find_str_2.encode('utf-8') in content:
                # PHP_XOR_BASE64/PHP_EVAL_XOR_BASE64类型的shell响应数据左右分别追加了16位混淆字符
                content_decoded = parse_response(
                    content, gen_key(ctx.options.key), ctx.options.charset)
                ctx.log.info("-" * 64)
                ctx.log.info(
                    "Decoded response content is: \n{}".format(content_decoded))
                ctx.log.info("-" * 64)
            else:
                # PHP_XOR_RAW类型的shell响应数据左右无任何追加字符
                content_decoded = parse_response_raw(
                    content, gen_key(ctx.options.key), ctx.options.charset)
                ctx.log.info("-" * 64)
                ctx.log.info(
                    "Decoded response content is: \n{}".format(content_decoded))
                ctx.log.info("-" * 64)


addons = [
    GodZilla()
]
