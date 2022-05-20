from njupass import NjuUiaAuth
from dotenv import load_dotenv
import os
import logging
from report import apply

def get_location():
    import random

    return random.choice(["江苏省南京市栖霞区九乡河东路", "江苏省南京市栖霞区仙林大道163号", "江苏省南京市栖霞区仙林湖路", "江苏省南京市栖霞区南京大学仙林校区逸夫楼",
                          "江苏省南京市栖霞区南大和园", "江苏省南京市南京大学仙林校区", "江苏省南京市栖霞区金大路",
                          "江苏省南京市南京大学仙林校区左涤江楼","江苏省南京市南京大学仙林校区图书馆", "江苏省南京市南京大学仙林校区星云楼"])


def login(username, password, logger, auth: NjuUiaAuth):
    """
    登录统一验证
    :return True 如果登录成功
    """
    logger.info('尝试登录...')

    if auth.needCaptcha(username):
        logger.info("统一认证平台需要输入验证码才能继续，尝试识别验证码...")
    ok = auth.tryLogin(username, password)
    if not ok:
        logger.error("登录失败。可能是用户名或密码错误，或是验证码无法识别。")
        return False

    logger.info('登录成功！')
    return True


if __name__ == "__main__":
    # Initialize authenticator
    auth = NjuUiaAuth()

    # Load environment
    load_dotenv(verbose=True)
    logging.basicConfig(
        level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s')
    log = logging.getLogger()

    username = os.getenv('NJU_USERNAME')
    password = os.getenv('NJU_PASSWORD')
    curr_location = get_location()
    method = os.getenv('COVID_TEST_METHOD')

    if method == '':
        method = 'YESTERDAY'

    if username == None or password == None or curr_location == None:
        log.error('账户、密码或地理位置信息为空！请检查是否正确地设置了 SECRET 项（GitHub Action）。')
        os._exit(1)

    # try to login
    ok = login(username, password, log, auth)
    if not ok:
        os._exit(-1)

    # start reporting
    ok = apply(curr_location, log, auth, force=True)
    if not ok:
        os._exit(-1)