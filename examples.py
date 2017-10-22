# -*- coding: utf-8 -*-

"""
示例
"""

from __future__ import print_function
# # from __future__ import unicode_literals

from procmon_xml_parser import *


# ---------------------------------------------------------------------------


def example_1():
    """
    1. 从 xml 文件创建 EventContainer() 对象(参数作用见函数说明)
    2. 保存为 json 文件
    3. 从 json 文件创建 EventContainer() 对象
    """
    ctr = EventContainer.from_xml_file(r"e:\tmp\logfile.xml", ["explorer.exe"], "run_default")
    ctr.remove_invalid_frames()
    ctr.save(r"e:\tmp\logfile_.json")

    ctr_again = EventContainer.from_json_file(r"e:\tmp\logfile_.json")

    # 打印内容
    ctr_again.print()


def example_2():
    """
    1. 组合几个 json 文件中的事件, 保存到新文件
    """
    ctr1 = EventContainer.from_json_file(r"e:\tmp\logfile_1.json")
    ctr2 = EventContainer.from_json_file(r"e:\tmp\logfile_2.json")
    ctr3 = EventContainer.from_json_file(r"e:\tmp\logfile_3.json")

    ctr_new = ctr1 + ctr2 + ctr3
    ctr_new.save(r"e:\tmp\logfile_new.json")

    # 打印内容
    ctr_new.print()


def example_3():
    """
    1. 堆重定向
    2. 模块重定向
    """
    ctr = EventContainer.from_json_file(r"e:\tmp\logfile.json")

    ctr.rebase_event_list_by_page_list([0x90000, 0xC0000, 0xD80000])
    ctr.rebase_event_list_by_md_list([0x400000, 0x407000, 0x10000000])

    ctr.save(r"e:\tmp\logfile_rebased.json")

    # 打印内容
    ctr.print()


def example_4():
    """
    1. 筛选调用栈包含指定 模块名称 的帧, 组成新的 EventContainer() 对象
    2. 筛选调用栈包含指定 堆起始地址 的帧, 组成新的 EventContainer() 对象
    """
    ctr = EventContainer.from_json_file(r"e:\tmp\logfile.json")

    ctr_explorer = ctr.new_by_itd_name("explorer.exe")
    ctr_0x90000 = ctr.new_by_page_start(0x90000)

    ctr_explorer.save(r"e:\tmp\logfile_explorer.json")
    ctr_0x90000.save(r"e:\tmp\logfile_0x90000.json")

    # 打印内容
    ctr_explorer.print()
    ctr_explorer.print()


def example_5():
    """
    1. 按指定的 感兴趣的模块名称列表 或 堆起始地址列表, 将 EventContainer() 对象分割为多个部分, 保存到指定目录
    2. [!+默认+!] 分割方式
    """
    ctr = EventContainer.from_json_file(r"e:\tmp\logfile.json")

    ctr.split_by_page_start([0x90000], r"e:\tmp\split_by_page_start_files")
    ctr.split_by_md_name(["explorer.exe"], r"e:\tmp\split_by_md_name_files")
    ctr.split(r"e:\tmp\split_default")


def example_6():
    """
    1. 创建 ConfigMgr() 对象加载配置
    2. 从配置文件加载配置, 修改, 保存
    """
    config = ConfigMgr()
    config.save()
    assert os.path.exists(config.config_file_path)

    config_again = ConfigMgr.from_json_file("config.json")
    config_again.add_oper("my_filter", ["RegSetValue"])
    config_again.save()


def example_7():
    """
    1. 用读取的配置文件, 过滤 EventContainer() 对象中的事件列表
    """
    ctr = EventContainer.from_json_file(r"e:\tmp\logfile.json")
    config = ConfigMgr.from_json_file("config.json")

    ctr_file = ctr.new_by_operation_list(config.get_oper_list("file"))
    ctr_reg = ctr.new_by_operation_list(config.get_oper_list("reg"))
    ctr_net = ctr.new_by_operation_list(config.get_oper_list("net"))
    ctr_proc = ctr.new_by_operation_list(config.get_oper_list("proc"))
    ctr_my_filter = ctr.new_by_operation_list(config.get_oper_list("my_filter"))

    ctr_file.save(r"e:\tmp\logfile_file.json")
    ctr_reg.save(r"e:\tmp\logfile_reg.json")
    ctr_net.save(r"e:\tmp\logfile_net.json")
    ctr_proc.save(r"e:\tmp\logfile_proc.json")
    ctr_my_filter.save(r"e:\tmp\logfile_my_filter.json")

    # 打印各自的内容
    ctr_file.print()
    ctr_reg.print()
    ctr_net.print()
    ctr_proc.print()
    ctr_my_filter.print()


def example_8():
    """
    1. 按不同过滤条件打印内容
    """
    ctr = EventContainer.from_json_file(r"e:\tmp\logfile.json")
    ctr.print_by_page_start_list([0x90000])
    ctr.print_by_md_name_list(["explorer.exe"])

    config = ConfigMgr.from_json_file("config.json")
    ctr.print_by_operation_list(config.get_oper_list("file"))
    ctr.print_by_operation_list(config.get_oper_list("net"))
    ctr.print_by_operation_list(config.get_oper_list("reg"))
    ctr.print_by_operation_list(config.get_oper_list("proc"))
    ctr.print_by_operation_list(config.get_oper_list("my_filter"))


def example_9():
    """
    1. 与 IDA 结合, 补全 ProcmonEvent 的内容
    """
    pass

# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
