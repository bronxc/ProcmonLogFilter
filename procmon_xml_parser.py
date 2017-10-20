# -*- coding: utf-8 -*-

"""
1. Python3, open() 可以指定 encoding, 所以需要 Python3 运行此脚本

2. 一步到位就得了, 别保存中间文件了

3.

"""

from __future__ import print_function
# # from __future__ import unicode_literals


import os
import json
from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# 变量


version = "0.1"


# ---------------------------------------------------------------------------
# util -

def __dup_file_name(file_path, append_text=None, new_ext=None):
    """
    由文件名生成 相关的 文件名

    @param: new_ext : string : (optional, dft=None)不带 "." 的后缀
    """
    splitext = os.path.splitext(file_path)
    if not new_ext:

        # 不改后缀

        if not append_text:
            # 不改后缀, 也不在名称后面添加内容, 就只加 "_00X" 这种
            for i in range(200):
                ret = os.path.join(os.path.dirname(file_path), os.path.basename(splitext[0]) + ("_%.3d" % i) + splitext[1])
                if not os.path.exists(ret):
                    return ret
        else:
            # 不改后缀, 在名称后面添加内容
            for i in range(200):
                ret = os.path.join(os.path.dirname(file_path), os.path.basename(splitext[0]) + append_text + ("_%.3d" % i) + splitext[1])
                if not os.path.exists(ret):
                    return ret
    else:
        # 更改后缀

        if not append_text:
            # 更改后缀, 也不在名称后面增加内容, 就只加 "_00X" 这种
            for i in range(200):
                ret = os.path.join(os.path.dirname(file_path), os.path.basename(splitext[0]) + ("_%.3d" % i) + "." + new_ext)
                if not os.path.exists(ret):
                    return ret
        else:
            # 更改后缀, 同时在名称后面增加内容
            for i in range(200):
                ret = os.path.join(os.path.dirname(file_path), os.path.basename(splitext[0]) + append_text + ("_%.3d" % i) + "." + new_ext)
                if not os.path.exists(ret):
                    return ret

    # 超过最大尝试次数了
    raise Exception("reach max try cnt when gen file name: %s" % file_path)

# ---------------------------------------------------------------------------
# 类


class StackFrameBase(object):
    """栈帧基类"""

    def __init__(self, addr_str):
        """
        @param: addr_str : string :
        """
        assert addr_str != "0x0"

        self.addr = int(addr_str, 16)

        self.func_addr = None
        self.addr_to_func_offset = None
        self.func_name = None

    # ---------------------------------------------------------------------------

    def __eq__(self, other):
        """
        比较是否是相同的地址

        - 两个比较的对象要有相同的 [模块基址/堆起始地址]
        """
        return self.addr == other.addr

    def __str__(self):
        """
        字符串表示

        - 基址什么的都可能还没设置过呢哦
        """
        if self.func_name:
            if self.addr_to_func_offset:
                return "0x%.8X(%s+0x%X)" % (self.addr, self.func_name, self.addr_to_func_offset)
            return "0x%.8X(%s)" % (self.addr, self.func_name)
        else:
            return "0x%.8X" % (self.addr)

    # ---------------------------------------------------------------------------

    def to_dict(self):
        raise Exception("implement by child class")

    @classmethod
    def from_dict(cls, dict_):
        raise Exception("implement by child class")

    # ---------------------------------------------------------------------------
    # END OF CLASS
    # ---------------------------------------------------------------------------


class StackFramePage(StackFrameBase):
    """堆上的栈帧"""

    def __init__(self, *args, **kwargs):
        assert args and len(args) == 1

        if isinstance(args[0], str):

            # 从 xml 的 <frame> 中创建
            addr_str = args[0]
            self.__init__raw(addr_str)

        elif isinstance(args[0], dict):

            # 从 json 中的 dict_ 中创建
            self.__init__dict(args[0])

        else:
            assert False

    def __init__raw(self, addr_str):
        """"""
        StackFrameBase.__init__(self, addr_str)

        self.page_start = None
        self.addr_to_page_offset = None
        self.func_to_page_offset = None

    def __init__dict(self, dict_):
        """"""
        self.addr = int(dict_["addr"], 16)

        if "func_addr" in dict_:
            self.func_addr = int(dict_["func_addr"], 16)
        else:
            self.func_addr = None

        if "addr_to_func_offset" in dict_:
            self.addr_to_func_offset = int(dict_["addr_to_func_offset"], 16)
        else:
            self.addr_to_func_offset = None

        if "func_name" in dict_:
            self.func_name = dict_["func_name"]
        else:
            self.func_name = None

        if "page_start" in dict_:
            self.page_start = int(dict_["page_start"], 16)
        else:
            self.page_start = None

        if "addr_to_page_offset" in dict_:
            self.addr_to_page_offset = int(dict_["addr_to_page_offset"], 16)
        else:
            self.addr_to_page_offset = None

        if "func_to_page_offset" in dict_:
            self.func_to_page_offset = int(dict_["func_to_page_offset"], 16)
        else:
            self.func_to_page_offset = None

    # ---------------------------------------------------------------------------

    def set_func_addr(self, func_addr):
        """
        设置函数地址

        数据来源: 从 IDA 遍历[函数起始地址 函数结束地址 函数名称]得到列表, 挨个匹配 self.addr 得到对应的函数, 传入其起始地址

        - 注意: 此时 self.page_start 与 IDA 中的模块基址应该是相同的
        """
        assert self.page_start

        self.func_addr = func_addr
        self.func_to_page_offset = func_addr - self.page_start
        self.addr_to_func_offset = self.addr - func_addr

    def set_func_name(self, func_name):
        """
        设置函数的名称

        数据来源: 从 IDA 遍历(以二进制方式加载的)[函数起始地址相对于 堆起始地址 的偏移]得到列表
                  挨个匹配 self.addr_to_md_offset 得到对应的函数, 传入其名称

        - 此处名称应该是有意义的, 要不然来个 sub_xxxx 有毛用
        """
        self.func_name = func_name

    def set_page_start(self, page_start):
        """
        设置实际执行时的 堆起始地址

        数据来源: ProcessMonitor.exe 运行时监控到的
        - 这里只设置 self.page_start/self.addr_to_page_offset, 如果是已经设置了 self.func_to_page_offset 等, 再来调用这个函数, 就不对了, 应该是调用 set_page_rebase() 了
        """
        self.page_start = page_start
        self.addr_to_page_offset = self.addr - self.page_start

    def set_page_rebase(self, page_rebase):
        """
        设置 IDA 中设置的 堆起始地址

        - 必然已经设置过 [堆起始地址], 要不也就不叫 re-base 了

        如果此基址不同于旧基址, 需要更新的内容:
            - self.page_start
            - self.addr
            - self.func_addr(如果设置了函数相对基址的偏移)
        """
        assert self.addr_to_page_offset

        if self.page_start != page_rebase:

            self.page_start = page_rebase
            self.addr = self.page_start + self.addr_to_page_offset
            if self.func_to_page_offset:
                self.func_addr = self.page_start + self.func_to_page_offset
        else:
            pass

    # ---------------------------------------------------------------------------

    def __str__for_ida(self):
        """
        字符串表示. 用于在 IDA 中添加注释. 主要是为了在 IDA 中能通过双击进行导航

        - 必然已经设置过 [堆起始地址].
        - 可以未设置 [IDA 堆起始地址], 就当跟运行时一样了

            - 无函数名                   - 0x901234
            - 函数名                     - 0x901234(__do_something)
            - 函数名+偏移                - 0x901234(__do_something+0x11)
        """
        assert self.page_start
        if self.func_name:
            if self.addr_to_func_offset:
                return "0x%.8X(%s+0x%X)" % (self.addr, self.func_name, self.addr_to_func_offset)
            return "0x%.8X(%s)" % (self.addr, self.func_name)
        else:
            return "0x%.8X" % (self.addr)

    # ---------------------------------------------------------------------------

    def to_dict(self):
        """转化成字典, 用于保存"""
        dict_ = {
            "frame_type": "page_frame",
            "addr": ("0x%.8X" % self.addr),
        }
        if self.func_addr:
            dict_["func_addr"] = ("0x%.8X" % self.func_addr)
        if self.func_name:
            dict_["func_name"] = self.func_name
        if self.addr_to_func_offset:
            dict_["addr_to_func_offset"] = ("0x%X" % self.addr_to_func_offset)
        if self.page_start:
            dict_["page_start"] = ("0x%.8X" % self.page_start)
        if self.addr_to_page_offset:
            dict_["addr_to_page_offset"] = ("0x%X" % self.addr_to_page_offset)
        if self.func_to_page_offset:
            dict_["func_to_page_offset"] = ("0x%X" % self.func_to_page_offset)

        return dict_

    @classmethod
    def from_dict(cls, dict_):
        """
        从 dict_ 创建一个自己对象

        @return: obj : StackFramePage() 对象
        """
        return StackFramePage(dict_)

    # ---------------------------------------------------------------------------
    # END OF CLASS
    # ---------------------------------------------------------------------------


class StackFrameModule(StackFrameBase):
    """模块上的栈帧"""

    def __init__(self, *args, **kwargs):
        """两种初始化方式"""
        assert args

        if len(args) == 3:

            # 从 xml 中的 <frame> 创建
            addr_str = args[0]
            path = args[1]
            location = args[2]
            self.__init__raw(addr_str, path, location)

        elif len(args) == 1:

            # 从 json 中的 dict_ 创建
            assert isinstance(args[0], dict)

            self.__init__dict(args[0])

        else:
            assert False

    def __init__raw(self, addr_str, path, location):
        """"""
        StackFrameBase.__init__(self, addr_str)

        self.md_base = None
        self.md_name = None

        if path:
            self.md_name = os.path.basename(path).lower()

        self.addr_to_md_offset = None
        self.func_to_md_offset = None

        assert " + " in location
        splits = location.split(" + ")
        self.func_name = splits[0]
        self.addr_to_func_offset = int(splits[1], 16)

    def __init__dict(self, dict_):
        """从 json 加载的 dict_ 中创建"""
        self.addr = int(dict_["addr"], 16)

        if "func_addr" in dict_:
            self.func_addr = int(dict_["func_addr"], 16)
        else:
            self.func_addr = None

        if "addr_to_func_offset" in dict_:
            self.addr_to_func_offset = int(dict_["addr_to_func_offset"], 16)
        else:
            self.addr_to_func_offset = None

        if "func_name" in dict_:
            self.func_name = dict_["func_name"]
        else:
            self.func_name = None

        if "md_base" in dict_:
            self.md_base = dict_["md_base"]
        else:
            self.md_base = None

        if "md_name" in dict_:
            self.md_name = dict_["md_name"]
        else:
            self.md_name = None

        if "addr_to_md_offset" in dict_:
            self.addr_to_md_offset = int(dict_["addr_to_md_offset"], 16)
        else:
            self.addr_to_md_offset = None

        if "func_to_md_offset" in dict_:
            self.func_to_md_offset = int(dict_["func_to_md_offset"], 16)
        else:
            self.func_to_md_offset = None

    # ---------------------------------------------------------------------------

    def set_func_addr(self, func_addr):
        """
        设置函数地址

        数据来源: 从 IDA 遍历[函数起始地址 函数结束地址 函数名称]得到列表, 挨个匹配 self.addr 得到对应的函数, 传入其起始地址

        - 注意: 此时 self.md_base 与 IDA 中的模块基址应该是相同的
        """
        assert self.md_base

        self.func_addr = func_addr
        self.func_to_md_offset = func_addr - self.md_base
        self.addr_to_func_offset = self.addr - func_addr

    def set_func_name(self, func_name):
        """
        设置函数的名称

        数据来源: 从 IDA 遍历(已 PE 方式加载的)[函数起始地址 函数结束地址 函数名称]得到列表
                  挨个匹配 self.addr_to_md_offset 得到对应的函数, 传入其名称

        - 此处名称应该是有意义的, 要不然来个 sub_xxxx 有毛用
        """
        self.func_name = func_name

    def set_md_base(self, md_base):
        """
        设置实际执行时的 模块基址

        数据来源: ProcessMonitor.exe 运行时监控到的
        """
        self.md_base = md_base
        self.addr_to_md_offset = self.addr - md_base

    def set_md_rebase(self, md_rebase):
        """
        设置 IDA 中设置的 模块基址, 为了能在 IDA 中导航

        - 必然已经设置过 [运行时模块基址], 要不也就不叫 re-base 了

        如果此基址不同于旧基址, 需要更新的内容:
            - self.md_base
            - self.addr
            - self.func_addr(如果设置了函数相对基址的偏移)
        """
        assert self.addr_to_md_offset

        if self.md_base != md_rebase:

            # 重定位

            self.md_base = md_rebase
            self.addr = self.addr_to_md_offset + self.md_base
            if self.func_to_md_offset:
                self.func_addr = self.func_to_md_offset + self.md_base
        else:
            # 不需重定位
            pass

    # ---------------------------------------------------------------------------

    def __str__for_ida(self):
        """
        字符串表示. 用于在 IDA 中添加注释. 主要是为了在 IDA 中能通过双击进行导航

        - 必然已经设置过 [运行时模块基址].
        - 可以未设置 [IDA 中的模块基址], 就当跟运行时一样了

            - 无函数名                   - 0x901234
            - 函数名                     - 0x901234(__do_something)
            - 函数名+偏移                - 0x901234(__do_something+0x11)

        - (模块名在这里没有鸟用, 所以这里其实跟 堆 是一样的)
        """
        assert self.md_base
        if self.func_name:
            if self.addr_to_func_offset:
                return "0x%.8X(%s+0x%X)" % (self.addr, self.func_name, self.addr_to_func_offset)
            return "0x%.8X(%s)" % (self.addr, self.func_name)
        else:
            return "0x%.8X" % (self.addr)

    # ---------------------------------------------------------------------------

    def to_dict(self):
        """转化成字典, 用于保存"""
        dict_ = {
            "frame_type": "module_frame",
            "addr": ("0x%.8X" % self.addr),
        }
        if self.func_addr:
            dict_["func_addr"] = ("0x%.8X" % self.func_addr)
        if self.func_name:
            dict_["func_name"] = self.func_name
        if self.addr_to_func_offset:
            dict_["addr_to_func_offset"] = ("0x%X" % self.addr_to_func_offset)
        if self.md_base:
            dict_["md_base"] = ("0x%.8X" % self.md_base)
        if self.md_name:
            dict_["md_name"] = self.md_name
        if self.addr_to_md_offset:
            dict_["addr_to_md_offset"] = ("0x%X" % self.addr_to_md_offset)
        if self.func_to_md_offset:
            dict_["func_to_md_offset"] = ("0x%X" % self.func_to_md_offset)

        return dict_

    @classmethod
    def from_dict(cls, dict_):
        """
        从 dict_ 创建一个自己对象

        @return: obj : StackFrameModule() 对象
        """
        return StackFrameModule(dict_)

    # ---------------------------------------------------------------------------
    # END OF CLASS
    # ---------------------------------------------------------------------------


class ProcmonEvent(object):
    """单次调用"""

    def __init__(self, *args, **kwargs):
        """"""
        if len(args) == 5:
            self.__init__raw(args[0], args[1], args[2], args[3], args[4])
        elif len(args) == 1:

            assert isinstance(args[0], dict)
            self.__init__dict(args[0])

        else:
            raise Exception("invalid param count for init ProcmonEvent: %s" % args)

    def __init__raw(self, operation, path, detail, frame_list, event_tag):
        """
        从 xml 中解析的 <event> Tag 创建对象

        @param: frame_list : list   : StackFrame() 对象列表, 而且无用项已经被去掉了
        @param: event_tag  : string : 此 xml 文件的 "tag", 例如: "run_default", "run_branch_1", "run_branch_2" 等
        """
        self.operation_list = [operation]
        self.path_list = [path]
        self.frame_list = frame_list
        self.event_tag_list = [event_tag]

        self.direct_invoke_api = None
        self.direct_invoke_api_invoke_inst = None

    def __init__dict(self, dict_):
        """
        从保存的 json 中 "恢复" 此对象

        - operation_list                : list   :
        - path_list                     : list   :
        - frame_list                    : list   :
        - event_tag_list                : list   :
        - direct_invoke_api             : string : 调用的 api. 有了这个, self.operation_list 就没有意义了
        - direct_invoke_api_invoke_inst : string : 调用 api 的指令. 例如: "call eax" "call [eax + 0xC]" "call dowrd_12345"
        """
        self.operation_list = dict_["operation_list"]
        self.path_list = dict_["path_list"]
        self.event_tag_list = dict_["event_tag_list"]

        if "direct_invoke_api" in dict_:
            self.direct_invoke_api = dict_["direct_invoke_api"]
        else:
            self.direct_invoke_api = None
        if "direct_invoke_api_invoke_inst" in dict_:
            self.direct_invoke_api_invoke_inst = dict_["direct_invoke_api_invoke_inst"]
        else:
            self.direct_invoke_api_invoke_inst = None

        frame_list_json = dict_["frame_list"]
        frame_list = []
        for frame_json in frame_list_json:

            if frame_json["frame_type"] == "page_frame":
                frame_list.append(StackFramePage.from_dict(frame_json))

            elif frame_json["frame_type"] == "module_frame":
                frame_list.append(StackFrameModule.from_dict(frame_json))

            else:
                raise Exception("invalid frame type from json: %s" % frame_json["frame_type"])
        self.frame_list = frame_list

    # ---------------------------------------------------------------------------

    def __eq__(self, other):
        """
        两个 调用堆栈 是否相同. 不管 proc_name/pid 之类的

        - 相同的调用路径, 其 Operation/Path/Detail 都可能不同
        - 例如一个 LoadLibrary 能导致很多个 Event, 都是同一个调用路径
        """
        if len(self.frame_list) != len(other.frame_list):
            return False

        for frame_my, frame_other in zip(self.frame_list, other.frame_list):
            if frame_my != frame_other:
                return False

        return True

    def __len__(self):
        """长度"""
        return len(self.frame_list)

    def __str__(self):
        """字符串表示"""
        tag_str = ""
        for tag in self.event_tag_list:
            tag_str = tag + "/" + tag_str
        tag_str = tag_str[:-1]

        oper_str = ""
        if self.direct_invoke_api:
            oper_str = "(api)" + self.direct_invoke_api
        else:
            for operation in self.operation_list:
                oper_str = operation + "/" + oper_str
            oper_str = oper_str[:-1]

        path_str = ""
        for path_ in self.path_list:
            if len(path_) != 0:
                path_str = path_ + "\n" + path_str
        if len(path_str) != 0:
            path_str = path_str[:-1]

        frame_str = ""
        for index, frame in enumerate(self.frame_list):
            frame_str = str(frame) + " -> " + frame_str
        if len(frame_str) != 0:
            frame_str = frame_str[:-4]

        if len(path_str) != 0:
            return tag_str + " - " + oper_str + ":\n" + path_str + ":\n" + frame_str
        else:
            return tag_str + " - " + oper_str + ":\n" + frame_str

    # ---------------------------------------------------------------------------
    # util

    def get_page_start_list(self):
        """获取所有的 self.frame_list 中的 page_start 集合"""
        page_start_list = []

        for frame in self.frame_list:
            if isinstance(frame, StackFramePage):

                # 并不一定所有 frame 的 堆起始地址 都设置了
                if frame.page_start and frame.page_start not in page_start_list:
                    page_start_list.append(frame.page_start)

        return page_start_list

    def check_any_frame_has_md_name(self, md_name):
        """检查 self.frame_list 中是否某个 frame.md_name == md_name"""
        for frame in self.frame_list:
            if isinstance(frame, StackFrameModule):

                # 匹配名称
                if frame.md_name == md_name:
                    return True

        # 没有匹配的
        return False

    def check_any_frame_has_page_start(self, page_start):
        """检查 self.frame_list 中是否某个 frame.page_start == page_start"""
        assert page_start

        for frame in self.frame_list:
            if isinstance(frame, StackFramePage):

                # 匹配 堆起始地址
                if frame.page_start and frame.page_start == page_start:
                    return True

        # 没有匹配的
        return False

    def merge(self, other):
        """
        当2个对象 调用堆栈 相同时, 将其内容混合

        - 如果有 direct_invoke_api, 则不管 operation_list
        """
        has_direct_invoke_api = False
        if self.direct_invoke_api and other.direct_invoke_api:
            assert self.direct_invoke_api == other.direct_invoke_api
            has_direct_invoke_api = True
        elif self.direct_invoke_api:
            has_direct_invoke_api = True
        elif other.direct_invoke_api:
            self.direct_invoke_api = other.direct_invoke_api
            has_direct_invoke_api = True
        else:
            pass

        # 没有调用的 api, 则混合 operation_list
        if not has_direct_invoke_api:
            self.operation_list = list(set(self.operation_list + other.operation_list))

        self.path_list = list(set(self.path_list + other.path_list))
        self.event_tag_list = list(set(self.event_tag_list + other.event_tag_list))

    # ---------------------------------------------------------------------------

    def to_dict(self):
        """将自身转化为 dict_"""
        dict_ = {
            "operation_list": self.operation_list,
            "path_list": self.path_list,
            "event_tag_list": self.event_tag_list,
        }

        if self.direct_invoke_api:
            dict_["direct_invoke_api"] = self.direct_invoke_api
        if self.direct_invoke_api_invoke_inst:
            dict_["direct_invoke_api_invoke_inst"] = self.direct_invoke_api_invoke_inst

        frame_list_json = []
        for frame in self.frame_list:
            frame_list_json.append(frame.to_dict())
        dict_["frame_list"] = frame_list_json

        return dict_

    @classmethod
    def from_dict(cls, dict_):
        """从 dict_ 中创建对象"""
        return ProcmonEvent(dict_)

    # ---------------------------------------------------------------------------
    # END OF CLASS
    # ---------------------------------------------------------------------------


class Output(object):
    """输出"""

    def __init__(self, *args, **kwargs):
        """"""
        if len(args) == 3:
            self.__init__dict(args[0], args[1], args[2])
        else:
            assert False

    def __init__dict(self, version, itd_md_list, event_list):
        """"""
        self.version = version
        self.itd_md_list = itd_md_list
        self.event_list = event_list

    def __str__(self):
        """字符串表示"""
        import pprint
        return pprint.pformat({
            "version": self.version,
            "itd_md_list": self.itd_md_list,
            "event_cnt": len(self.event_list)
        })

    # ---------------------------------------------------------------------------

    def __validate_same_direct_invoke_api_retnto_addr(self):
        """有同 1 个 direct_invoke_api_retnto_addr 的 event"""
        group_dict = {}
        for evt in self.event_list:
            if len(evt.frame_list) > 1:
                if evt.frame_list[1].addr not in group_dict:
                    group_dict[evt.frame_list[1].addr] = [evt]
                else:
                    group_dict[evt.frame_list[1].addr].append(evt)
        # 输出
        for addr, evt_list in group_dict.items():
            if len(evt_list) != 1:

                print("evt return to same addr: 0x%.8X:" % (addr))

                _1st_func_name_list = []
                for evt in evt_list:
                    if evt.frame_list[0].func_name not in _1st_func_name_list:
                        _1st_func_name_list.append(evt.frame_list[0].func_name)
                print("1st frame func name list: %s" % str(_1st_func_name_list))

                print("event details:")
                for evt in evt_list:
                    print(evt)
                    print("")
                print("\n\n")

    def __validate_same_1st_frame_funcname(self):
        group_dict = {}
        for evt in self.event_list:
            if len(evt.frame_list) > 0:
                if evt.frame_list[0].func_name not in group_dict:
                    group_dict[evt.frame_list[0].func_name] = [evt]
                else:
                    group_dict[evt.frame_list[0].func_name].append(evt)
        # 输出
        for func_name, evt_list in group_dict.items():
            if len(evt_list) != 1:

                print("evt with same 1st funcname: %s:" % (func_name))

                direct_invoke_api_retnto_addr_list = []
                direct_invoke_api_retnto_addr_list_str = ""
                for evt in evt_list:
                    if evt.frame_list[1].addr not in direct_invoke_api_retnto_addr_list:
                        direct_invoke_api_retnto_addr_list.append(evt.frame_list[1].addr)
                        direct_invoke_api_retnto_addr_list_str += " 0x%.8X " % evt.frame_list[1].addr
                print("this 1st func name return to those addrs: %s" % direct_invoke_api_retnto_addr_list_str)

                print("event details:")
                for evt in evt_list:
                    print(evt)
                    print("")
                print("\n\n")

    def validate(self):
        """自检, 输出些信息"""
        # self.__validate_same_direct_invoke_api_retnto_addr()
        self.__validate_same_1st_frame_funcname()

    # ---------------------------------------------------------------------------
    # util -

    # ---------------------------------------------------------------------------
    # 内容补全

    def guess_direct_invoke_api(self):
        """猜测 direct_invoke_api"""

        _1st_func_name_as_direct_api_list = [
            "LoadLibrary",
            "CopyFile",
            "GetFileAttributes",
            "GetComputerName",
            "GetFileSize",
        ]

        _1st_func_name_to_direct_api_dict = {
            "ElfCloseEventLog": "RegCreateKey",
            "EtwpMapEventToEventRecord": "RegEnumKey",
        }

        for evt in self.event_list:
            # 没有 direct_invoke_api 且调用栈不为空的
            if not evt.direct_invoke_api and len(evt.frame_list) > 0:

                frame_1st = evt.frame_list[0]

                # 第1帧的函数名作为 direct_invoke_api
                for api_str in _1st_func_name_as_direct_api_list:
                    if frame_1st.func_name.startswith(api_str):
                        evt.direct_invoke_api = api_str
                        break

                # 第1帧的函数名转换后作为 direct_invoke_api
                for api_str, api_invoke in _1st_func_name_to_direct_api_dict.items():
                    if frame_1st.func_name.startswith(api_str):
                        evt.direct_invoke_api = api_invoke
                        break

                #

    def export_unguessable_direct_invoke_api_retn_addrs(self):
        """
        导出不能猜测 direct_invoke_api 的 evt 的 direct_invoke_api_retnto_addr, 借助 IDA 来判断具体的 api

        这里采用 frame.addr. 所以调用此函数之前, 请考虑清楚是不是需要重定位基址之类的
        """
        retnto_addr_list = []
        for evt in self.event_list:
            if not evt.direct_invoke_api and len(evt.frame_list) > 1:

                addr = evt.frame_list[1].addr
                if addr not in retnto_addr_list:

                    # 将此地址作为 direct_invoke_api_retnto_addr
                    retnto_addr_list.append(addr)

        # 返回
        return retnto_addr_list

    def complete_direct_invoke_api(slef, file_path):
        """用 IDA 解析的内容, 补全 evt.direct_invoke_api"""
        pass

    def complete_event_frame_by_md_func_list(self, md_name, md_func_list):
        """用 函数范围/名称 列表补全 event.frame_list 的内容"""
        for evt in self.event_list:
            for frame in evt.frame_list:
                if isinstance(frame, StackFrameModule) and frame.md_name == md_name:

                    # 遍历函数范围

                    for func_tuple in md_func_list:

                        # 这里直接比较地址, 所以要确保两者的基址是一样的
                        if func_tuple[0] <= frame.addr and frame.addr <= func_tuple[1]:

                            # 设置函数地址和名称

                            frame.set_func_addr(func_tuple[0])
                            if not func_tuple[2].startswith("sub_"):
                                frame.set_func_name(func_tuple[2])

    def complete_event_frame_by_page_func_list(self, page_start, page_func_list):
        """用 函数范围/名称 列表补全 event.frame_list 的内容"""
        for evt in self.event_list:
            for frame in evt.frame_list:
                if isinstance(frame, StackFramePage) and frame.page_start == page_start:

                    # 遍历函数范围

                    for func_tuple in page_func_list:

                        # 这里直接比较地址, 所以要确保两者的基址是一样的
                        if func_tuple[0] <= frame.addr and frame.addr <= func_tuple[1]:

                            # 设置函数地址和名称

                            frame.set_func_addr(func_tuple[0])
                            if not func_tuple[2].startswith("sub_"):
                                frame.set_func_name(func_tuple[2])

    def complete_event_frame_by_md_func_file(self, md_name, md_func_file_path):
        """
        用 .txt 文件中的内容补全 event.frame_list 的内容

        - 文件的格式:
            - func_start func_end func_name
            - func_start func_end func_name
            - ...
        - 数据来源: IDA 脚本解析
        - 注意: IDA 中的基址, 与对应的 frame.md_base 应该是相同的, 不然补全个屁啊
        """
        with open(md_func_file_path, mode='r', encoding='utf-8') as f:

            md_func_list = []

            # 解析文件
            for line in f.readlines():

                splits = line.strip().split(" ")

                func_start = int(splits[0], 16)
                func_end = int(splits[1], 16)
                func_name = splits[2]

                md_func_list.append(func_start, func_end, func_name)

            # 补全
            self.complete_event_frame_by_md_func_list(md_name, md_func_list)

    def complete_event_frame_by_page_func_file(self, page_start, page_func_file_path):
        """
        用 .txt 文件中的内容补全 event.frame_list 的内容

        - 文件的格式:
            - func_start func_end func_name
            - func_start func_end func_name
            - ...
        - 数据来源: IDA 脚本解析
        - 注意: IDA 中的基址, 与对应的 frame.page_start 应该是相同的, 不然补全个屁啊
        """
        with open(page_func_file_path, mode='r', encoding='utf-8') as f:

            page_func_list = []

            # 解析文件
            for line in f.readlines():

                splits = line.strip().split(" ")

                func_start = int(splits[0], 16)
                func_end = int(splits[1], 16)
                func_name = splits[2]

                page_func_list.append(func_start, func_end, func_name)

            # 补全
            self.complete_event_frame_by_page_func_list(page_start, page_func_list)

    # ---------------------------------------------------------------------------
    # 分割

    def split_by_md_name(self, itd_md_list, output_dir):
        """分割出 frame 中包含指定 md_name 的事件"""
        output_file_path_template = os.path.join(output_dir, "log_split", "log.json")

        for md_name in itd_md_list:

            # 匹配模块名称

            output_event_list = []
            for evt in self.event_list:
                if evt.check_any_frame_has_md_name(md_name):
                    output_event_list.append(evt)
            if len(output_event_list) != 0:

                # 输出到文件

                output_file_name = __dup_file_name(output_file_path_template, append_text="_" + md_name)
                self.to_json_file(output_file_name, self.version, [md_name], output_event_list)

            else:
                # 此模块无相关事件
                print("no event related with md: %s" % md_name)
                pass

    def split_by_page_start(self, page_start_list, output_dir):
        """分割出 frame 中包含 page_start 的事件"""
        output_file_path_template = os.path.join(output_dir, "log_split", "log.json")

        for page_start in page_start_list:

            # 匹配堆起始地址

            output_event_list = []
            for evt in self.event_list:
                if evt.check_any_frame_has_page_start(page_start):
                    output_event_list.append(evt)
            if len(output_event_list) != 0:

                # 输出到文件

                output_file_name = __dup_file_name(output_file_path_template, append_text=("_0x%.8X" % page_start))
                self.to_json_file(output_file_name, self.version, [], output_event_list)

            else:
                # 此模块无相关事件
                print("no event related with page_start: 0x%.8X" % page_start)
                pass

    def split(self, output_dir):
        """
        默认分割

        - 按照 self.itd_md_list 和 frame 中所有 page_start 来分割
        """
        # 检查/创建目录
        if not os.path.exists(output_dir):
            os.path.mkdir(output_dir)

        # 模块名称

        if len(self.itd_md_list) != 0:
            self.split_by_md_name(self.itd_md_list, output_dir)

        # 堆起始地址

        # 收集
        page_start_list = []
        for evt in self.event_list:
            evt_page_start_list = evt.get_page_start_list()
            if evt_page_start_list and len(evt_page_start_list) != 0:
                page_start_list = list(set(page_start_list + evt_page_start_list))
        # 判断并分割/输出
        if len(page_start_list) != 0:
            self.split_by_page_start(page_start_list, output_dir)

    # ---------------------------------------------------------------------------
    # 重定向

    def __rebase_frame_by_md_name(self, frame, md_rebase_list):
        """
        按照 md_name 重定位

        @param: frame          : obj  :
        @param: md_rebase_list : list : tuple 列表. tuple 元素: (md_rebase_name, md_old_base, md_old_end, md_new_base)

        @return: bool : True, 表示成功重定位; False, 条件不符合
        """
        assert isinstance(frame, StackFrameModule)

        if frame.md_base is None:

            # 未设置过模块基址, 先设置基址, 再重定位

            for md_rebase_tuple in md_rebase_list:

                # 比较名称
                md_rebase_name = md_rebase_tuple[0]
                if frame.md_name == md_rebase_name:

                    md_old_base = md_rebase_tuple[1]
                    md_old_end = md_rebase_tuple[2]
                    md_new_base = md_rebase_tuple[3]

                    assert md_old_base <= frame.addr and frame.addr <= md_old_end

                    # 设置模块基址
                    frame.set_md_base(md_old_base)

                    # 重定位模块基址
                    frame.set_md_rebase(md_new_base)

                    # print("rebased module frame %s from 0x%.8X to 0x%.8X" % (frame, md_old_base, md_new_base))

                    return True

            # 所有模块名称都不匹配
            return False

        else:

            # 已经设置过模块基址, 挨个匹配看是否需要重定位

            for md_rebase_tuple in md_rebase_list:

                # 比较名称
                md_rebase_name = md_rebase_tuple[0]
                if frame.md_name == md_rebase_name:

                    # 比较基址
                    md_old_base = md_rebase_tuple[1]
                    if md_old_base != frame.md_base:

                        # 比较模块范围, 确定 frame 的地址在正确的范围之内
                        md_old_end = md_rebase_tuple[2]
                        if md_old_base <= frame.addr and frame.addr <= md_old_end:

                            # 重定位
                            md_new_base = md_rebase_tuple[3]
                            frame.set_md_rebase(md_new_base)

                            # print("rebased module frame %s from 0x%.8X to 0x%.8X" % (frame, md_old_base, md_new_base))

                            return True

                        else:
                            # 地址范围不对, 提示一下
                            print("frame addr not in md range when rebase")
                            pass
                    else:
                        # 基址是一样的, 不需要重定位
                        pass

                    # 这个模块名匹配上了, 但出问题了, 其他的就不匹配了
                    return False

                else:
                    # 此模块名不匹配
                    pass

            # 所有模块名称都不匹配
            return False

    def __rebase_frame_by_page(self, frame, page_rebase_list):
        """
        按照 page_start-page_end 重定位

        @param: frame            : obj  :
        @param: page_rebase_list : list : tuple 列表. tuple 元素: (old_page_start, old_page_end, new_page_start)
        """
        assert isinstance(frame, StackFramePage)

        if not frame.page_start:

            # 还没设置过堆起始地址, 用提供的重定位信息设置堆起始地址

            for page_rebase_tuple in page_rebase_list:

                # 判定范围是否符合
                old_page_start = page_rebase_tuple[0]
                old_page_end = page_rebase_tuple[1]
                if old_page_start <= frame.addr and frame.addr <= old_page_end:

                    # 符合, 设置堆起始地址
                    frame.set_page_start(old_page_start)

                    # 然后重定位
                    new_page_start = page_rebase_tuple[2]
                    frame.set_page_rebase(new_page_start)

                    # print("rebased page frame %s from 0x%.8X to 0x%.8X" % (frame, old_page_start, new_page_start))

                    return True

            # 所有范围都不匹配, 没有符合要求的重定位信息
            return False

        else:
            # 已经设置过堆起始地址, 用提供的重定位信息重新设置堆起始地址

            for page_rebase_tuple in page_rebase_list:

                # 比较堆起始地址
                old_page_start = page_rebase_tuple[0]
                if frame.page_start != old_page_start:

                    # 比较堆地址范围, 确定 frame 的地址在正确的范围之内
                    old_page_end = page_rebase_tuple[1]
                    if old_page_start <= frame.addr and frame.addr <= old_page_end:

                        # 重定位
                        new_page_start = page_rebase_tuple[2]
                        frame.set_page_rebase(new_page_start)

                        # print("rebased page frame %s from 0x%.8X to 0x%.8X" % (frame, old_page_start, new_page_start))

                        return True

                    else:
                        # 堆起始地址对的上, 但是帧地址却不在堆的范围之内
                        print("frame addr not in page range when rebase")
                        pass

                    # 这个起始地址匹配上了, 其他的就不匹配了
                    return False

                else:
                    # 堆起始地址没变, 不需要重定位
                    pass

            # 所有范围都不匹配
            return False

    def rebase_event_list_by_md_list(self, md_rebase_list):
        """根据模块名称和地址, 重定向 ProcmonEvent() 列表"""
        for evt in self.event_list:

            # 遍历帧
            for frame in evt.frame_list:

                if isinstance(frame, StackFrameModule):

                    # 模块上的帧都要试试看
                    if md_rebase_list and self.__rebase_frame_by_md_name(frame, md_rebase_list):
                        # print("rebased frame based on md_name: %s" % (frame))
                        pass

    def rebase_event_list_by_page_list(self, page_rebase_list):
        """根据堆的范围, 重定向 ProcmonEvent() 列表"""
        for evt in self.event_list:

            # 遍历帧
            for frame in evt.frame_list:

                if isinstance(frame, StackFramePage):

                    # 堆上的帧都要试试看
                    if page_rebase_list and self.__rebase_frame_by_page(frame, page_rebase_list):
                        # print("rebased frame based on page: %s" % (frame))
                        pass

    # ---------------------------------------------------------------------------
    # 混合/等价替换/去重

    def __add__(self, other):
        """
        相同版本的 Output 对象混合到一起

        - 要加就把两堆 ProcmonEvent() 对象加到一起, 因为每次添加都要执行 去重/组合 等操作, 如果一个一个加就太慢了
        - 最好重定位都是正确的, 要不然, 呵呵...

        - 不提供 self.merge_from_xml_file()/self.merge_from_json_file() 的操作. 请先通过 xml_file/json_file 创建 Output 对象, 再让2个对象 +
        """
        # 比较版本
        if self.version != other.version:
            raise Exception("can't merge 2 Output object with different version: %s vs %s" % (self.version, other.version))

        # 对于模块名不相同的, 警告下, 后果用户自己承担吧...
        new_itd_md_list = self.itd_md_list
        if set(self.itd_md_list) != set(other.itd_md_list):
            print("merge 2 Output object with different itd module list: %s vs %s" % (self.itd_md_list, other.itd_md_list))
            new_itd_md_list = list(set(self.itd_md_list + other.itd_md_list))

        # 混合
        new_event_list = self.merge_duplicate_event_list(list(self.event_list + other.event_list))

        # 返回新对象
        return Output(self.version, new_itd_md_list, new_event_list)

    def diff(self, other):
        """比较2个 Output() 对象的不同"""
        pass

    def equalvent_event_list(self):
        """
        等价转换某些 event

        转换规则:
            - LoadLibrary
        """

        for evt in self.event_list:

            # 确保是没有 merge 过的 event
            assert len(evt.operation_list) == 1
            assert len(evt.path_list) == 1
            operation = evt.operation_list[0]
            # path = evt.path_list[0]

            # 肯定是以 evt.frame_list 作为 "等价" 的切入点和依据
            if len(evt.frame_list) > 0:

                frame_1st = evt.frame_list[0]

                # LoadLibrary

                if frame_1st.func_name.startswith("LoadLibrary"):

                    print("equalventing evt with LoadLibrary to Load Image. evt:\n%s\n" % evt)

                    evt.operation_list[0] = "Load Image"
                    if operation in ["RegQueryValue", "RegOpenKey", "RegCreateKey"]:
                        evt.path_list[0] = ""

                # CopyFileW

                if frame_1st.func_name.startswith("CopyFile"):

                    print("equalventing evt with CopyFile to CopyFile. evt:\n%s\n" % evt)

                    evt.operation_list[0] = "CopyFile"
                    if operation in ["RegQueryValue", "RegOpenKey", "RegCreateKey"]:
                        evt.path_list[0] = ""

                # GetFileAttributes

                if frame_1st.func_name.startswith("GetFileAttributes"):

                    print("equalventing evt with GetFileAttributes to GetFileAttributes. evt:\n%s\n" % evt)

                    evt.operation_list[0] = "GetFileAttributes"
                    if operation in ["RegQueryValue", "RegOpenKey", "RegCreateKey"]:
                        evt.path_list[0] = ""

                # KiFastCallEntry - 这个得靠 IDA 救场

                # ElfCloseEventLog           - RegCreateKey, operation 就是这个
                # EtwpProcessTraceLog        - RegOpenKey, operation 就是这个

                # gethostname/gethostbyname 会导致很多 RegQueryValue, 而且中间有 procmon 无法识别的系统模块帧
                # 0x00DB928F/0x00DB92B7

    def merge_duplicate_event_list(self):
        """ProcmonEvent() 对象列表去重"""

        print("%d procmon event to remove duplicate" % (len(self.event_list)))

        # 按长度分组
        grouped_event_dict = {}
        for evt in self.event_list:
            if len(evt) not in grouped_event_dict:
                grouped_event_dict[len(evt)] = [evt]
            else:
                grouped_event_dict[len(evt)].append(evt)

        filtered_event_dict = {}

        # 每组内去重
        for len_, evt_group in grouped_event_dict.items():

            # 过滤相同长度的
            for index, evt in enumerate(evt_group):

                if index == 0:
                    # 首个, 不过滤, 添加到列表
                    filtered_event_dict[len_] = [evt]

                else:
                    # 过滤非首个
                    is_allready_in = False
                    for evt_added in filtered_event_dict[len_]:
                        if evt == evt_added:

                            # 已经添加过了, 把它的内容 merge 到相同 frame_list 的 event 中
                            is_allready_in = True
                            evt_added.merge(evt)

                            break

                    if not is_allready_in:
                        filtered_event_dict[len_].append(evt)

        # 返回列表
        filtered_event_list = []
        for len_, evt_group in filtered_event_dict.items():
            filtered_event_list = list(filtered_event_list + evt_group)

        print("%d procmon event remained..." % (len(filtered_event_list)))
        self.event_list = filtered_event_list

    def remove_frames_procmon_recognized_sysmd_as_heap(self):
        """
        去除 procmon 将系统模块帧识别为堆帧的帧

        - 把 frame.addr 以 0x70000000 开头的 frame
        """
        for evt in self.event_list:

            # 将符合条件的帧添加到删除列表
            remove_frame_list = []
            for frame in evt.frame_list:
                if isinstance(frame, StackFramePage) and frame.addr > 0x70000000:
                    remove_frame_list.append(frame)

            # 删除
            if len(remove_frame_list) != 0:
                print("remove %d frames procmon recognized sysmd as heap for evt:\n%s\n" % (len(remove_frame_list), evt))
                for frame_remove in remove_frame_list:
                    evt.frame_list.remove(frame_remove)

    # ---------------------------------------------------------------------------
    # json

    def save(self, json_file_path):
        """保存到 json 文件"""
        self.to_json_file(json_file_path, self.version, self.itd_md_list, self.event_list)

    @classmethod
    def to_json_file(cls, json_file_path, version, itd_md_list, event_list):
        """保存到 json 文件"""
        event_list_json = []
        for evt in event_list:
            event_list_json.append(evt.to_dict())

        dict_ = {
            "version": version,
            "itd_md_list": itd_md_list,
            "event_list": event_list_json
        }
        with open(json_file_path, mode='w', encoding='utf-8') as f:
            f.write(json.dumps(dict_, ensure_ascii=False, indent=4))
            print("save json output to file: %s" % json_file_path)
            return

        print("open json output file fail: %s" % json_file_path)

    @classmethod
    def from_json_file(cls, json_file_path):
        """读取 json 文件, 创建此对象"""
        with open(json_file_path, mode='r', encoding='utf-8') as f:
            dict_ = json.load(f)

            version = dict_["version"]
            itd_md_list = dict_["itd_md_list"]
            event_list_json = dict_["event_list"]
            event_list = []
            for evt_json in event_list_json:
                event_list.append(ProcmonEvent.from_dict(evt_json))

            print("output info loaded from file: %s" % json_file_path)

            return Output(version, itd_md_list, event_list)

        print("open json file fail: %s" % json_file_path)
        return None

    # ---------------------------------------------------------------------------
    # xml

    @classmethod
    def __clear_soup(cls, soup, itd_md_list):
        """去掉 processlist 和 stack 不合格的 event"""
        # processlist
        soup.processlist.decompose()
        print("processlist decomposed!")

        # event

        print("%d event Tags to filter..." % len(soup.find_all("event")))
        del_cnt = 0
        for evt in soup.find_all("event"):

            is_del = True

            for frame in evt.find_all("frame"):
                if frame.path is None:
                    # 堆上的栈帧, 此 event 保留
                    is_del = False
                    break

                for md in itd_md_list:
                    if md in frame.path.text:
                        # 感兴趣模块的栈帧, 此 event 保留
                        is_del = False
                        break

                if not is_del:
                    break

            if is_del:
                # 从 soup 中清空此事件内容
                # print("decompose evt %s" % evt.Operation.text)
                evt.decompose()
                del_cnt += 1

        print("%d event Tags decomposed" % del_cnt)
        print("%d event Tags remaining..." % len(soup.find_all("event")))

        return soup

    @classmethod
    def __frame_tag_to_stackframe(cls, frame_tag):
        """xml 中的 <frame> Tag 转为 StackFrameBase() 对象"""
        addr_str = frame_tag.address.text

        if frame_tag.path is None:
            assert frame_tag.location is None
            return StackFramePage(addr_str)

        return StackFrameModule(addr_str, frame_tag.path.text, frame_tag.location.text)

    @classmethod
    def __to_event_list(cls, soup, itd_md_list, event_tag):
        """将 soup 中所有的 <event> Tag 转换为 ProcmonEvent() 对象"""
        event_list = []
        # 遍历 <event> Tag
        for evt in soup.find_all("event"):

            frame_tag_list = evt.find_all("frame")
            frame_list = []

            # 遍历 <frame> Tag
            for index, frame_tag in enumerate(frame_tag_list):

                is_ignore_frame = True
                if frame_tag.address.text == "0x0":
                    # 顶部的 0x0, 忽略
                    pass

                elif not frame_tag.path:

                    # 堆上的帧, 保留
                    # 这里依据 frame_tag.path 判断是否在堆上, 有可能导致: 某些 procmon 无法识别的系统模块的帧被作为堆上的帧
                    # 然而, 毕竟没有什么有效的解决方案
                    # 在 <modulelist> 里面去找 ??

                    is_ignore_frame = False

                else:
                    for md_name in itd_md_list:
                        if md_name in frame_tag.path.text:
                            # 感兴趣模块的帧, 保留
                            is_ignore_frame = False
                            break

                if not is_ignore_frame:

                    # 需要添加此帧

                    if len(frame_list) == 0:

                        # 判断是不是第1个帧, 如果是, 则把前一个加为第1个帧
                        frame_list.append(cls.__frame_tag_to_stackframe(frame_tag_list[index - 1]))

                    frame_list.append(cls.__frame_tag_to_stackframe(frame_tag))

                else:
                    # 忽略此帧
                    # print("ignore frame: %s" % (frame_tag.address.text))
                    pass

            # 添加到 ProcmonEvent() 对象列表
            event = ProcmonEvent(evt.Operation.text, evt.Path.text, evt.Detail.text, frame_list, event_tag)
            event_list.append(event)

        print("%d event Tag converted to ProcmonEvent object" % len(event_list))

        # 返回
        return event_list

    @classmethod
    def from_xml_file(cls, file_path, itd_md_list, event_tag, version="0.1"):
        """
        读取 xml 文件, 创建此对象

        @return: obj/None : Output() 对象
        """
        # 检查/补全参数
        if len(event_tag) == 0:
            raise Exception("must specify a event_tag for this xml log file")
        if len(itd_md_list) == 0:
            print("no itd md list specified. will only leave event with heap frames")

        # 读取并解析 xml 文件
        with open(file_path, mode='r', encoding='utf-8') as f:

            # 创建 soup 对象
            print("initializing raw soup...")
            soup = BeautifulSoup(f, "xml")
            print("initialized raw soup...")

            # 清理
            soup = cls.__clear_soup(soup, itd_md_list)

            # 转为 ProcmonEvent() 对象列表
            event_list = cls.__to_event_list(soup, itd_md_list, event_tag)

            # 创建对象并返回
            return Output(version, itd_md_list, event_list)

        print("open xml file fail: %s" % file_path)

        # 返回 None
        return None

    # ---------------------------------------------------------------------------
    # END OF CLASS
    # ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# - 函数


def test():
    pass


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":

    if False:

        xml_file_path = r"e:\tmp\logfile.xml"

        # 创建对象
        output = Output.from_xml_file(xml_file_path, ["explorer.exe"], "run_default")

        # 重定向
        output.rebase_event_list_by_page_list([(0x90000, 0xF0000, 0xD80000)])

        # 等价转换某些 ProcmonEvent()
        output.equalvent_event_list()

        # 混合调用栈相同的 ProcmonEvent()
        output.merge_duplicate_event_list()

        # 去除 procmon 将系统模块帧识别为堆帧的帧
        output.remove_frames_procmon_recognized_sysmd_as_heap()

        # 保存到文件
        output.save(__dup_file_name(xml_file_path, new_ext="json"))

    else:
        json_file_path = r"e:\tmp\logfile_000.json"

        obj = Output.from_json_file(json_file_path)

        # 猜测 direct_invoke_api
        # obj.guess_direct_invoke_api()

        # 保存
        # obj.save(__dup_file_name(json_file_path))

        # obj.validate()

        addrs = obj.export_unguessable_direct_invoke_api_retn_addrs()
        for addr in addrs:
            print("0x%.8X" % addr)

        # for evt in obj.event_list:
        #     # if len(evt.frame_list) > 0 and evt.frame_list[0].func_name.startswith("KiFastCallEntry"):
        #     #     print(evt)
        #     #     print("\n")
        #     print(evt)
        #     print("\n")

    #
    pass

# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
