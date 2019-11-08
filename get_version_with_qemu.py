'''
@author: ysg
@time: 2019年11月08日09:31:20
脚本用于提取解压后固件中常见组件的版本信息
'''
import os,logging,struct
import subprocess, re
import argparse
logger = logging.getLogger("get_version.py")
logger.setLevel(logging.INFO)
DEFAULT_COMPONENT = ['busybox', "iptables", "updatedd"]

class Component_emulation():
    def __init__(self, firmware_rootfs, componet_list = None, archinfo = None):
        self.componet_list = componet_list if componet_list else DEFAULT_COMPONENT #待识别的组件二进制执行命令
        self._firmware_rootfs = firmware_rootfs #固件的根目录
        self._archinfo = archinfo # 固件中可执行文件的架构信息
        self._version_param = ["--version", "-V", "-v", ""] # 输出版本信息需要的附加参数，例如--version
        self._comp_version = {} #记录得到的版本信息
    def build_environment(self):
        if self._firmware_rootfs[-1] != '/':
            self._firmware_rootfs = self._firmware_rootfs+'/'
        if not self._archinfo:
            logger.error("No arch info")
            raise Exception
        self._qemu_name = ""
        if self._archinfo == 'mipsel':
            self._qemu_name = "qemu-mipsel-static"
        elif self._archinfo == "mipsb":
            self._qemu_name = "qemu-mips-static"
        elif self._archinfo == 'armel':
            self._qemu_name = 'qemu-arm-static'
        elif self._archinfo == 'armb':
            self._qemu_name = 'qemu-armeb-static'
        else:
            logger.error("not support arch %s" % self._archinfo)
            raise Exception
        cp_qemu_cmd = """cp `which %(qemu)s` %(firmware_rootfs)s""" % {"qemu":self._qemu_name,
                                                                       "firmware_rootfs":self._firmware_rootfs}
        s,o = subprocess.getstatusoutput(cp_qemu_cmd)

    def clear_environment(self):
        pass

    def change_component_list(self):
        pass

    def identify_arch(self):
        '''
        得到固件中ELF文件的架构信息
        :return:
        '''
        def _get_arch_from_header(filename):
            end = ""
            arch = ""
            with open(filename, 'rb') as f:
                if f.read(4) == b'\x7fELF':
                    file_type = f.read(1)
                    if file_type == b'\x01':
                        endianness = f.read(1)
                        if endianness == b'\x01':
                            #little
                            end = "el"
                        else:
                            end = "b"
                    elif file_type == b'\x02':
                        pass
                        logger.warning("64bit ELF!")
                    else:
                        logger.error("error file type")
                        raise Exception
                    f.read(10)
                    f.read(2)
                    e_machine = f.read(2)
                    e_machine = struct.unpack(">H",e_machine) if end=='b' else struct.unpack("<H",e_machine)
                    e_machine = e_machine[0]
                    if e_machine == 8 or e_machine == 10:
                        arch = "mips"
                    elif e_machine == 20 :
                        arch = 'powerpc'
                    elif e_machine == 40:
                        arch='arm'
                    else:
                        logger.error("not support machine code %s" % e_machine)
            return arch+end
        #首先尝试 busybox
        guessed_busybox_path = os.path.join(self._firmware_rootfs, 'bin/busybox')
        if os.path.exists(guessed_busybox_path):
            self._archinfo = _get_arch_from_header(guessed_busybox_path)
        else:
            #尝试init
            guessed_init_path = os.path.join(self._firmware_rootfs,"sbin/init")
            if os.path.exists(guessed_init_path):
                self._archinfo = _get_arch_from_header(guessed_init_path)
            else:
                logger.error("could not get arch information with busybox and init!")
                raise Exception
    def _locate_componet(self, componet_name):
        cname = os.path.basename(componet_name)
        find_cmd = """find %(rootfs)s -name %(component)s""" %{"rootfs":self._firmware_rootfs,
                                                               "component":componet_name}
        out = subprocess.getoutput(find_cmd)
        if out=="":
            logger.warning("can not locate the %s in firmware" % componet_name)
            return ""
        else:
            local_path=out.split(self._firmware_rootfs)[1]
            # if local_path.startswith("/"):
            #     local_path = "."+local_path
        return local_path

    def build_command(self, componet_name, version_param):
        '''
        :param componet_name: 待执行的版本名称
        :return: qemu 用户级仿真命令
        '''
        cmd = """sudo chroot %(rootfs)s /%(qemu_name)s %(component)s %(version_param)s"""%{
            "rootfs":self._firmware_rootfs,
            "qemu_name":self._qemu_name,
            "component":componet_name,
            "version_param": version_param
        }
        return cmd
    def _check_version(self, cmd):
        '''
        qemu执行并且获得输出信息，判断是否得到版本信息
        :param cmd: qemu执行命令
        :return: True or False
        '''
        logger.info("qemu cmd : %s" % cmd)
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        outinfo = p.stdout.read()
        try:
            p.wait(1)
        except subprocess.TimeoutExpired:
            logger.warning('cmd is TimeoutExpired  %s' % cmd)
            p.terminate()
        return outinfo

    def _real_version(self, outinfo, componet):
        '''
        判断组件运行时输出信息是不是真的包含版本信息，是的话返回True
        :param outinfo: 组件运行时的输出信息
        :param componet: 组件名
        :return: True or False
        '''
        version_str_pattern = re.compile(b"[0-9]{1,4}\.[0-9]{1,4}")
        for line in outinfo.split(b"\n"):
            if componet.lower().encode("utf-8") in line.lower():
                res = version_str_pattern.search(line)
                if res:
                    logger.info("Version Match ok, target is %s" % line)
                    self._comp_version[componet] = bytes.decode(line)
                    return True
        return False

    def get_verions(self):
        if not self._archinfo:
            self.identify_arch()
        self.build_environment()
        for componet in self.componet_list:
            componet_path = self._locate_componet(componet)
            if componet_path == "":
                continue
            for version_param in self._version_param:
                cmd = self.build_command(componet_path, version_param)
                outinfo = self._check_version(cmd)
                if self._real_version(outinfo, componet):
                    break
        return self._comp_version
    def dump_versions(self):
        return self._comp_version

if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument("firmware_rootfs", help="The path of file system root to your extracted firmware")
    argparser.add_argument("-c","--component", nargs='+',help="The component names you want to get version from\n such as -c busybox telnetd")
    args = argparser.parse_args()
    componet = args.component if args.component else None
    ce = Component_emulation(firmware_rootfs=args.firmware_rootfs, componet_list=componet)
    dic = ce.get_verions()
    for key in dic:
        print("%s: %s"%(key, dic[key]))
