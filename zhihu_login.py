# -*- coding: utf-8 -*-
# @Time    : 2021-01-10 15:34
# @Author  : Kevin_Wang
# @File    : zhihu_login.py

import requests
import time
import hmac
import hashlib
import json
import base64
import execjs
import re
from requests.utils import dict_from_cookiejar, cookiejar_from_dict
from redis import StrictRedis
from captcha_predict import Api
from urllib.parse import urlencode
from requests_toolbelt.multipart.encoder import MultipartEncoder


login_url = 'https://www.zhihu.com/api/v3/oauth/sign_in'
# 先调用一次，判断是否需要验证码
captcha_url = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=en'

js_path = 'zhihu_encrypt.js'


class ZhiHuLogin:
    """
    知乎模拟登录，实现验证码处理，body加密，参数解析
    """

    def __init__(self):
        # login的参数,需要加密再post
        self.login_params = {
            'clientId': 'c3cef7c66a1843f8b3a9e6a1e3160e20',  # signature参数
            'grantType': "password",  # signature参数
            'timestamp': 0,
            'source': "com.zhihu.web",  # signature参数
            'signature': '',
            'username': "+86你的手机",
            'password': "密码",
            'captcha': '',
            'lang': "en",
            'utm_source': '',
            'refSource': "other_https://www.zhihu.com/signin?next=%2F",
        }
        self.session = requests.session()
        self.session.headers = {
            'accept-encoding': 'gzip, deflate, br',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/86.0.4240.111 Safari/537.36',
            'origin': 'www.zhihu.com',
            'referer': 'https://www.zhihu.com/signin?next=%2F',
        }
        # 打码网站的账号id和key
        self.pd_id = 'your_pd_id'
        self.pd_key = 'your_pd_key'
        # 识别验证码的类型，30表示字母数字组合，400表示4位验证码
        self.pred_type = '30400'

    def login(self):
        """
        登录的入口
        :return: 如果登录成功则返回成功登录的session,否则返回None
        """
        cookies = self.get_cookies()
        # 验证cookies是否有效，有效的话就直接返回这个session就行了，不用再登录
        if self.check_cookies(cookies):
            self.session.cookies = cookies
            print('登录成功')
            return self.session

        timestamp = int(time.time() * 1000)
        # 验证码识别，不需要的话为空字符串, 识别有问题返回-1
        captcha = self.get_captcha(str(timestamp // 1000))
        if not isinstance(captcha, int):
            print('验证码识别失败，请重试')
            return
        # 更新login_params，其中signature需要计算得出
        self.login_params.update({
            'timestamp': timestamp,
            'captcha': captcha,
            'signature': self.get_signature(timestamp)
        })
        headers = self.session.headers.copy()
        _xsrf = self.get_xsrf()
        if not _xsrf:
            print('xsrftoken获取失败，请重试')
            return
        headers.update({
            'x-xsrftoken': _xsrf,
            # 不知道是什么版本信息，没有这个会报错
            'x-zse-83': '3_2.0',
            'content-type': 'application/x-www-form-urlencoded',
            'x-requested-with': 'fetch',
        })

        # 加密login_params
        encrypted_data = self.encrypt_body(self.login_params)
        resp = self.session.post(login_url, data=encrypted_data, headers=headers)

        if resp.status_code == 201:
            print('登录成功')
            return self.session

        print('登录失败，错误信息：%s' % json.loads(resp.text)['error'])
        return None

    def get_xsrf(self):
        """
        获取headers中的xsrftoken，需要请求一次登录界面，请求完之后会把xsrf写在cookies里
        :return: xsrftoken/'' 如果是空字符串，说明获取的不对
        """
        if '_xsrf' in self.session.cookies:
            return self.session.cookies.get('_xsrf')
        self.session.get('https://www.zhihu.com/signin?next=%2F', allow_redirects=False)

        return self.session.cookies.get('_xsrf', '')

    def get_signature(self, tm):
        """
        计算signature的方法
        :param tm: int：13位时间戳
        :return: 加密结果
        """
        key = b'd1b964811afb40118a12068ff74a12f4'
        hm = hmac.new(key, digestmod=hashlib.sha1)
        message = self.login_params['grantType'] + self.login_params['clientId'] + self.login_params['source']
        message += str(tm)
        hm.update(message.encode('utf-8'))

        return hm.hexdigest()

    def get_captcha(self, tm):
        """
        验证码的处理，最多需要调用三次接口，至少要调用一次来确认是否需要验证码
        :param tm: str: 10位验证码
        :return: str/-1 如果不需要验证码，返回空字符串，如果需要则返回识别成功的验证码或者-1（识别识别的时候）
        """
        # 第一次调用确认是否需要验证码
        resp = self.session.get(captcha_url)
        show_captcha = json.loads(resp.text)['show_captcha']

        if show_captcha:
            # 如果需要验证码的话，则put一次获取验证码的图片信息
            pus_res = self.session.put(captcha_url)
            pus_res_dict = json.loads(pus_res.text)
            # base64的格式，其中要把%E2%86%B5替换成%0A
            img_base64 = pus_res_dict['img_base64'].replace('%E2%86%B5', '%0A')
            # 打码网站的调用实例
            api = Api(self.pd_id, self.pd_key)
            pred_resp = api.predict(self.pred_type, base64.b64decode(img_base64), tm)
            if pred_resp.ret_code == 0:
                capt = pred_resp.rsp_data
                headers = self.session.headers.copy()
                headers.update(
                    {
                        'x-xsrftoken': self.get_xsrf(),
                        'x-ab-param': 'se_ffzx_jushen1=0;li_edu_page=old;tp_topic_style=0;top_test_4_liguangyi=1'
                                      ';zr_expslotpaid=1;tp_zrec=0;qap_question_visitor= '
                                      '0;qap_question_author=0;tp_dingyue_video=0;pf_noti_entry_num=0'
                                      ';li_paid_answer_exp=0;li_vip_verti_search=0;tp_contents=2;pf_adjust=0'
                                      ';li_panswer_topic=0;zr_slotpaidexp=1;li_sp_mqbk=0;li_video_section=0',
                        'x-ab-pb': 'ClhSC2AL4QuWCxsARwD0C+AABwzmANcLaABCAA8MTAvkCsIAzwt1DLcACABkDD8A4At5ALQKmwsP'
                                   'C8UAbACkAK0ANwxWDAELiQzsCmcAtAA0DCYMtQvcC4sAEiwBAAEAAAAAAAAAAAIFAAAAAQsAAQI'
                                   'AAAAAAAIAAAAAAAEBAAABAAAAAAMAAA==',
                        'x-requested-with': 'fetch',
                     })
                # 识别成功后要再post一次给服务器，
                # 这里post的格式是multipart-formdata，boundary都是----WebKitFormBoundary开头的，
                # 这里直接指定了一个，测试是ok的
                multipart_formdata = MultipartEncoder(fields={'input_text': capt},
                                                      boundary='----WebKitFormBoundary9rNe5nyAAj9qbqcF')
                headers['content-type'] = multipart_formdata.content_type
                # 把验证码单独post一次给服务器，再在登录的data里再提交一次，两次提交一致就通过啦
                resp = self.session.post(captcha_url, data=multipart_formdata.to_string(), headers=headers)
                # 提交验证成功会返回success的response
                if json.loads(resp.text)['success']:
                    return capt
                else:
                    api.justice(pred_resp.request_id)
                    return -1
            else:
                return -1
        else:
            return ''

    def encrypt_body(self, body):
        """加密form_data，加密的js代码进行了混淆，同时还做了一个操作时间的校验，
        所以很难靠抓包来还原，这里直接调用了js代码来执行加密算法
        :param body: dict，form-data"""
        # 加密前要把form-data的key做一下转换
        body = self.exchange_body_key(body)
        body_str = urlencode(body)

        with open(js_path, 'r', encoding='utf-8') as f:
            js = f.read()
        ctx = execjs.compile(js, cwd=r'C:\Users\49576\AppData\Roaming\npm\node_modules')
        encrypted_body = ctx.call('b', body_str)

        return encrypted_body

    def exchange_body_key(self, body):
        """
        把form-data的key做一次转换，从大写字母中分割开，两边用_连接，然后切换成小写
        其实可以一开始就直接用这种格式命名...但是一开始没反应过来...
        写都写了...别浪费...
        :param body: 完整的需要加密的form-data
        :return: lower_body: 转换后的form-data
        """
        pattern = r'([A-Z]+[^A-Z]*)'
        lower_body = {}
        for key, value in body.items():
            # 用正则表达式匹配，然后分割并用_join起来
            lower_key = '_'.join(filter(None, re.split(pattern, key))).lower()
            lower_body[lower_key] = value

        return lower_body

    def save_cookies(self):
        """
        把cookies转换为字符串并存在redis里
        :return: 0/1：是否插入成功
        """
        cookie = self.session.cookies
        # print(type(cookie))
        # 先转换为字典
        cookie_dict = dict_from_cookiejar(cookie)
        # 再转换为str
        cookie_str = json.dumps(cookie_dict)
        client = StrictRedis()
        # 先删除已经存储的cookie
        client.spop('zhihu')
        return client.sadd('zhihu', cookie_str)

    def get_cookies(self):
        """
        从redis中读取存储的cookie_str，转换成cookie格式
        :return: cookies或空字符串，空字符串表示没有存储的cookie
        """
        client = StrictRedis()
        cookie_str = client.smembers('zhihu')
        if not cookie_str:
            return ''
        cookies_dict = json.loads(cookie_str)
        cookie = cookiejar_from_dict(cookies_dict)

        return cookie

    def check_cookies(self, cookies):
        """
        使用redis中的cookie登录首页，校验cookie是否有效，如果没有跳转，说明cookie还有效，有跳转则说明cookie已经失效了
        :return: bool
        """
        session = requests.session()
        # 没有存储的cookie，需要登录获取
        if isinstance(cookies, str):
            return False
        session.cookies = cookies
        index_url = 'http://www.zhihu.com'
        headers = self.session.headers.copy()

        resp = session.get(index_url, headers=headers, allow_redirects=False)
        if resp.status_code == 200:
            return True

        return False
