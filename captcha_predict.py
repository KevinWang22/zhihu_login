# -*- coding: utf-8 -*-
# @Time    : 2021-01-10 15:02
# @Author  : Kevin_Wang
# @File    : captcha_predict.py
import requests
import hashlib
import json
import time

FATEA_PRED_URL = "http://pred.fateadm.com"


class Rsp:

    def __init__(self):
        # 调用状态码，只有为0的时候才是成功调用，其他状态码意义见：http://docs.fateadm.com/web/#/1?page_id=5
        self.ret_code = -1
        self.err_msg = ''
        self.request_id = ''
        self.rsp_data = ''
        # 用户余额
        self.cust_val = 0.0

    def parse_json_rsp(self, rsp_data):
        if not rsp_data:
            self.err_msg = '无返回值'
            return
        json_rsp = json.loads(rsp_data)
        self.ret_code = int(json_rsp['RetCode'])
        self.err_msg = json_rsp['ErrMsg']
        self.request_id = json_rsp['RequestId']
        if self.ret_code == 0:
            json_result_data = json.loads(json_rsp['RspData'])
            if 'result' in json_result_data:
                self.rsp_data = json_result_data['result']
            if 'cust_val' in json_result_data:
                self.cust_val = float(json_result_data['cust_val'])


def cal_sign(pd_id, pd_key, timestamp):
    """
    计算post请求的sign
    :param pd_id: str 用户id，在用户中心可查
    :param pd_key: str  用户key，在用户中心可查
    :param timestamp: str 时间戳
    :return: 16进制sign值 str
    """
    md5 = hashlib.md5()
    md5.update((timestamp + pd_key).encode())
    temp_sign = md5.hexdigest()

    md5 = hashlib.md5()
    md5.update((pd_id + timestamp + temp_sign).encode())

    return md5.hexdigest()


def api_request(url, body_data, img_data=''):
    """
    调用api进行识别，对不同操作（识别，查询余额，退款）都是同一个调用方式，只是api不同
    :param url:  api，
    :param body_data:  post数据
    :param img_data: 图片数据，只有做图片识别的时候需要，其他为空
    :return: 上面的rsp实例
    """
    rsp = Rsp()
    post_data = body_data
    files = {
        'img_data': ('img_data', img_data),
    }
    header = {
        'user-agent': 'Mozilla/5.0'
    }

    resp = requests.post(url, data=post_data, files=files, headers=header)
    rsp.parse_json_rsp(resp.text)

    return rsp


class Api:
    """Api调用类，包括：query_balance:余额查询; predict:验证码识别; justice:退款"""

    def __init__(self, pd_id, pd_key):
        self.pd_id = pd_id
        self.pd_key = pd_key
        self.host = FATEA_PRED_URL

    def query_balance(self):
        """
        查询账户余额
        :return: resp 查询结果的Rsp实例，定义在上面，以便做后续处理
        """
        tm = str(int(time.time()))
        sign = cal_sign(self.pd_id, self.pd_key, tm)
        param = {
            'user_id': self.pd_id,
            'timestamp': tm,
            'sign': sign,
        }
        url = self.host + '/api/custval'
        resp = api_request(url, param)
        if resp.ret_code == 0:
            print('接口调用成功，余额: %s, err_msg: %s, 识别结果: %s' % (resp.cust_val, resp.err_msg, resp.rsp_data))
        else:
            print(f'接口调用失败，ret_code:{resp.ret_code}, err_msg:{resp.err_msg}')

        return resp

    def predict(self, pred_type, img_data, tm):
        """
        调用接口识别验证码
        :param pred_type: str 验证码类型, 30400 = 4位数字英文
        :param img_data:  图片数据，如果图片在本地，需要先读取
        :param tm: str 时间戳
        :return: 识别结果
        """
        sign = cal_sign(self.pd_id, self.pd_key, tm)
        post_data = {
            'user_id': self.pd_id,
            'timestamp': tm,
            'sign': sign,
            'predict_type': pred_type,
            # 使用Multipart/form-data形式直接上传图片数据
            'up_type': 'mt',
        }
        url = self.host + '/api/capreg'
        files = img_data
        resp = api_request(url, post_data, files)
        if resp.ret_code == 0:
            print(f'调用接口成功，识别结果：{resp.rsp_data}')
        else:
            print(f'调用接口失败，ret_code:{resp.ret_code}, err_msg:{resp.err_msg}, ret_data:{resp.rsp_data}')

        return resp

    def justice(self, request_id):
        """
        退款接口
        只有成功识别了才会扣钱，如果识别的结果不正确，可以发起退款申请
        :param request_id: 发起识别的request_id，在调用接口识别的返回信息中有
        :return: 调用退款接口返回的Rsp实例
        """
        tm = str(int(time.time()))
        sign = cal_sign(self.pd_id, self.pd_key, tm)
        params = {
            'User_id': self.pd_id,
            'timestamp': tm,
            'sign': sign,
            'request_id': request_id
        }
        url = self.host + '/api/capjust'
        resp = api_request(url, params)
        if resp.ret_code == 0:
            print(f'{request_id}退款成功，err_msg:{resp.err_msg}')
        else:
            print(f'{request_id}退款失败，错误码:{resp.ret_code}，错误信息:{resp.err_msg}')

        return resp

