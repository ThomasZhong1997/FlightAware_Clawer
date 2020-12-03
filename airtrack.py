import requests
import json
import pymysql
import time
import threading
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import random
import ssl
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from multiprocessing import Process
from multiprocessing import Manager
import os

# 浏览器常用的User-Agent头，用于模拟浏览器进行请求，可有效避免被判定为恶意请求
user_agent = ["Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
              "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
              "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
              "Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
              "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
              "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
              "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
              "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
              "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
              "Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
              "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
              "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
              "Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
              "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko Fedora/1.9.0.8-1.fc10 Kazehakase/0.5.6",
              "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
              "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52"
              ]

# 设置请求的最大重试次数为5次
requests.adapters.DEFAULT_RETRYS = 5


def reflash_token(semaphore, token_list, token_list_lock):
    base_url = "https://flightaware.com/live/"
    front_time = time.mktime(time.localtime())
    firstTime = True
    try:
        while True:
            now_time = time.mktime(time.localtime())
            time_interval = now_time - front_time
            if semaphore.value > 0:
                if time_interval < 500 and not firstTime:
                    continue
            firstTime = False
            # 清空代理信息
            front_time = now_time
            d = DesiredCapabilities.CHROME
            d['loggingPrefs'] = {'performance': 'ALL'}
            chrome_options = Options()
            # chrome_options.add_argument('--proxy-server={0}'.format(proxy))
            chrome_options.add_experimental_option('w3c', False)
            # 启动谷歌浏览器驱动
            driver = webdriver.Chrome(desired_capabilities=d, chrome_options=chrome_options)
            driver.set_page_load_timeout(120)
            # 浏览器访问目标网站，监视抓取网络请求信息
            while True:
                try:
                    driver.get(base_url)
                except TimeoutException:
                    driver.execute_script("window.stop()")
                except Exception:
                    continue
                entries = driver.get_log('performance')
                if len(entries) != 0:
                    break
            # 在所有网络请求中解析出目标URL中的Token
            print('token threading need token lock')
            token_list_lock.acquire()
            print('token threading get token lock')
            for entry in entries:
                entry = json.loads(entry['message'])
                if 'request' in entry['message']['params'].keys():
                    url = entry['message']['params']['request']['url']
                    if url[:63] == 'https://zh.flightaware.com/ajax/ignoreall/vicinity_aircraft.rvt':
                        token_index = url.find('token=')
                        now_token = url[token_index + 6:]
                        if now_token not in token_list:
                            token_list.append(now_token)
            semaphore.value = len(token_list)
            token_list_lock.release()
            print('token threading release token lock')
            driver.close()
            del driver
    except TimeoutException:
        reflash_token(semaphore, token_list, token_list_lock)


def airtrack_data_request(process_id, boundary, token):
    # # 连接Mysql数据库
    # connection = pymysql.connect(host='localhost', port=3306, user='root', password='111111',
    #                              database='airplanetrack')
    # # 获取数据库指针
    # cursor = connection.cursor()
    upload_time = ''
    try:
        # 根据Token和提取范围构建请求URL
        url = 'https://flightaware.com/ajax/ignoreall/vicinity_aircraft.rvt?&minLon=' + str(
            boundary[0]) + '&minLat=' + str(
            boundary[2]) + '&maxLon=' + str(boundary[1]) + '&maxLat=' + str(
            boundary[3]) + '&token=' + token.value
        # 构建请求头，关闭Keep-Alive
        headers = {'User-Agent': random.choice(user_agent),
                   'Connection': 'close'}
        s = requests.session()
        s.keep_alive = False
        # 取消HTTPS请求的SSL验证
        ssl._create_default_https_context = ssl._create_unverified_context
        # 抓取可能存在的异常
        try:
            web_response = s.get(url, headers=headers, verify=False, timeout=20)
        except requests.exceptions.ConnectTimeout as e:
            print("request connected timeout error!")
            return -1
        except requests.exceptions.Timeout as e:
            print("request timeout error!")
            return -1
        except Exception as e:
            print(url)
            return 0
        if web_response.status_code != 200:
            print('error')
            return 0
        # 解析返回的结果，设置返回结果的编码
        web_response.encoding = 'utf8'
        # 按编码获取返回结果的内容
        response_text = web_response.text
        # 将返回的字符串转换为JSON对象，便于进行解析
        json_obj = json.loads(response_text)
        features = json_obj['features']

        # 记录数据获取的时间
        upload_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        now_date, now_time = upload_time.split(' ')
        year, month, day = now_date.split('-')
        folder = year + month + day

        # 安全打开文件
        with open('data/' + folder + '/' + process_id + '.txt', 'a') as f:
            # 解析每条数据中的内容并写入文件
            for i in range(len(features)):
                one_feature = features[i]
                feature_geometry = one_feature['geometry']['coordinates']
                longitude = feature_geometry[0]
                latitude = feature_geometry[1]
                feature_properties = one_feature['properties']
                flight_id = feature_properties['flight_id']
                prefix = feature_properties['prefix']
                direction = feature_properties['direction']
                plane_type = feature_properties['type']
                identify = feature_properties['ident']
                icon = feature_properties['icon']
                ga = feature_properties['ga']
                ori_icao = feature_properties['origin']['icao']
                ori_iata = feature_properties['origin']['iata']
                dest_icao = feature_properties['destination']['icao']
                dest_iata = feature_properties['destination']['iata']
                prominence = feature_properties['prominence']
                if 'altitude' in feature_properties.keys():
                    altitude = feature_properties['altitude']
                else:
                    altitude = -1

                if 'groundspeed' in feature_properties.keys():
                    groundspeed = feature_properties['groundspeed']
                else:
                    groundspeed = -1

                if 'projected' in feature_properties.keys():
                    projected = feature_properties['projected']
                else:
                    projected = -1

                output_str = str(longitude) + ',' + str(latitude) + ',' + str(flight_id) + ',' + str(prefix) + ',' + str(
                    plane_type) + ',' + str(identify) + ',' + str(icon) + ',' + str(ga) + ',' + str(
                    ori_icao) + ',' + str(ori_iata) + ',' + str(dest_icao) + ',' + str(
                    dest_iata) + ',' + str(prominence) + ',' + str(altitude) + ',' + str(groundspeed) + ',' + str(
                    projected) + ',' + str(upload_time) + ',' + str(direction) + '\n'
                f.write(output_str)
            f.close()
            print('this request will insert ' + str(len(features)) + ' records --' + str(upload_time) + ' insert success!')
    except TimeoutException as e:
        print(e)
    finally:
        abc = 0
    return 1


# 请求核函数
def request_thread_core(process_id, boundary, semaphore, token, token_list_lock, token_list):
    # 无限请求
    while True:
        # 信号量大于等于0可以进入下一步
        if semaphore.value >= 0:
            # 若当前token不存在则不可请求
            if token.value != '':
                # 开始请求
                flag = airtrack_data_request(process_id, boundary, token)
                # 异常处理，若返回1则表示请求且插入成功，写入日志
                if flag == 1:
                    print(process_id + ' process insert success!')
                    f = open('logs/' + str(process_id) + '_process.log', 'a')
                    f.write('Insert Success! ' + 'Time: ' + str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())) + '\n')
                    f.close()
                    time.sleep(30)
                # 若请求失败则说明当前Token已过期，从token_list中获取一个新的token
                else:
                    print('Process ' + process_id + ': need token_lock')
                    token_list_lock.acquire()
                    print('Process ' + process_id + ': get token_lock')
                    if semaphore.value > 0:
                        token.value = token_list.pop()
                        semaphore.value -= 1
                    token_list_lock.release()
                    print('Process ' + process_id + ': release token_lock')
                    f = open('logs/' + str(process_id) + '_process.log', 'a')
                    f.write('Change Token! ' + 'Time: ' + str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())) + '\n')
                    f.close()
                    time.sleep(5)
            # 若当前没有Token，则不断尝试从list中获取Token
            else:
                print('Process ' + process_id + ': need token_lock')
                token_list_lock.acquire()
                print('Process ' + process_id + ': get token_lock')
                if semaphore.value > 0 and token.value == '':
                    token.value = token_list.pop(0)
                    semaphore.value -= 1
                token_list_lock.release()
                print('Process ' + process_id + ': release token_lock')
                time.sleep(10)


def create_data_table_core():
    try:
        while True:
            # 连接Mysql数据库
            connection = pymysql.connect(host='localhost', port=3306, user='root', password='111111',
                                         database='airplanetrack')
            # 获取数据库指针
            cursor = connection.cursor()
            next_day_timestamp = time.mktime(time.localtime())
            next_day_timestamp += 60 * 60 * 24
            datetime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(next_day_timestamp))
            now_date, now_time = datetime.split(' ')
            year, month, day = now_date.split('-')
            table_name = 'airplanepoint_world_' + year[2:] + month + day
            search_sql = 'show tables like \'' + table_name + '\';'
            print('search_sql: ' + search_sql)
            table_number = cursor.execute(search_sql)
            if table_number == 0:
                create_table_sql = 'create table ' + table_name + ' like airplanepoint_world_191113;'
                print('create_table_sql: ' + create_table_sql)
                cursor.execute(create_table_sql)
            connection.commit()
            connection.close()
            time.sleep(24 * 60 * 60)
    except Exception as e:
        print(e)


# 每天新建一个存放数据的文件夹
def create_data_dictionary_core():
    while True:
        next_day_timestamp = time.mktime(time.localtime())
        next_day_timestamp += 60 * 60 * 24
        datetime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(next_day_timestamp))
        now_date, now_time = datetime.split(' ')
        year, month, day = now_date.split('-')
        folder_name = year + month + day
        if not os.path.exists('data/' + folder_name):
            os.mkdir('data/' + folder_name)
        time.sleep(60 * 60 * 24)


if __name__ == '__main__':
    p_manager = Manager()
    # 全局变量：token，用于线程更新Token
    token = p_manager.Value('token', '')
    token_list = p_manager.list()
    # 信号量
    semaphore = p_manager.Value('semaphore', 0)
    #锁
    token_list_lock = p_manager.Lock()

    # 用于实时更新网站Token的线程，每270秒请求一次网页获取token
    p = threading.Thread(target=reflash_token, args=(semaphore, token_list, token_list_lock))
    p.start()

    # 每天创建一张新表
    tp = threading.Thread(target=create_data_dictionary_core, args=())
    tp.start()

    # 主进程等待120秒，等待线程1与线程2得到Token与IP
    time.sleep(10)
    # 每隔20秒向网站请求一次数据并存入数据库
    # 由于此API一次最多返回1000条数据，因此将全球的数据分为22块进行请求
    boundary_list = list()
    boundary_list.append([-180, -30, -90, 20])
    boundary_list.append([-180, -90, 20, 30])
    boundary_list.append([-180, -90, 30, 40])
    boundary_list.append([-180, -90, 40, 90])
    boundary_list.append([-90, -30, 20, 30])
    boundary_list.append([-90, -30, 30, 40])
    boundary_list.append([-90, -30, 40, 90])
    boundary_list.append([-30, 30, -90, 20])
    boundary_list.append([-30, 0, 20, 90])
    boundary_list.append([0, 15, 20, 90])
    boundary_list.append([15, 30, 20, 90])
    boundary_list.append([30, 180, -90, -20])
    boundary_list.append([30, 105, -20, 20])
    boundary_list.append([105, 180, -20, 20])
    boundary_list.append([30, 120, -20, 0])
    boundary_list.append([30, 120, 0, 20])
    boundary_list.append([30, 120, 20, 25])
    boundary_list.append([30, 120, 25, 30])
    boundary_list.append([30, 120, 30, 40])
    boundary_list.append([30, 120, 40, 60])
    boundary_list.append([30, 120, 60, 90])
    boundary_list.append([120, 180, 20, 40])
    boundary_list.append([120, 180, 40, 90])

    # 开启22个线程进行请求
    for i in range(len(boundary_list)):
        t = threading.Thread(target=request_thread_core, args=(str(i), boundary_list[i],  semaphore, token, token_list_lock, token_list))
        t.start()
        time.sleep(5)
