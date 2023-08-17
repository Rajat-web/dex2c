#!/usr/bin/env python
# coding=utf-8
import os
from shutil import copy
from sys import argv
from androguard.core.androconf import show_logging
import subprocess
import sys
from logging import getLogger, INFO
from androguard.core.bytecodes import apk, dvm


def backup_filters(filters_path="filter.txt"):
    temp_filters = "temp-filter.txt"
    copy(filters_path, temp_filters)
    os.remove(filters_path)
    return temp_filters


def restore_filters(temp_filters):
    copy(temp_filters, "filter.txt")
    os.remove(temp_filters)


def get_method_signature(method_info):
    signature = method_info[0] + method_info[1]

    if isinstance(method_info[2], list):
        for param in method_info[2]:
            signature += param.replace(" ", "")
    else:
        signature += method_info[2].replace(" ", "")

    return signature


def get_dialog_hook():
    # Don't keep invoke-static {p0}, part
    # Don't keep ->, remove it from method signature

    return "Lcom/google/android/material/navigation/NavigationWidget;initializeActivity(Landroid/content/Context;)Lcom/google/android/material/navigation/NavigationWidget;"


def get_dialog_classes():
    return [
        "Lcom/google/android/material/navigation/NavigationWidget;",
        "Lcom/google/android/material/navigation/NavigationWidget$1;",
        "Lcom/google/android/material/navigation/NavigationWidget$OnInitializationChange;",
    ]


if __name__ == "__main__":
    backup_filter = backup_filters()

    try:
        index_of_input = -1

        if "-a" in argv:
            index_of_input = argv.index("-a") + 1
        elif "--input" in argv:
            index_of_input = argv.index("--input") + 1
        else:
            raise Exception("No input apk file found")

        show_logging(level=INFO)

        hooked_methods = list()

        getLogger("dcc").info("Loading apk file")
        apk_file = apk.APK(argv[index_of_input], skip_analysis=True)
        raw_dex_files = apk_file.get_all_dex()
        getLogger("dcc").info("Apk file loaded")
        dex_files = list()

        getLogger("dcc").info("Loading dex files")
        for raw_dex_file in raw_dex_files:
            try:
                dex_files.append(dvm.DalvikVMFormat(raw_dex_file))
            except Exception as ex:
                getLogger("dcc").error("Couldn't load dex", exc_info=True)

        for dex_file in dex_files:
            for current_class in dex_file.get_classes():
                methods = current_class.get_methods()

                for method in methods:
                    code = method.get_code()

                    if code is None:
                        continue

                    for instruction in code.get_bc().get_instructions():
                        op_value = instruction.get_op_value()

                        if (0x6E <= op_value <= 0x72) or (0x74 <= op_value <= 0x78):
                            idx_meth = instruction.get_ref_kind()
                            method_info = instruction.cm.vm.get_cm_method(idx_meth)

                            if (
                                not method_info is None
                                and get_method_signature(method_info)
                                == get_dialog_hook()
                            ):
                                (
                                    class_name,
                                    method_name,
                                    method_descriptor,
                                ) = method.get_triple()

                                hooked_methods.append(
                                    class_name
                                    + ";"
                                    + method_name
                                    + method_descriptor.replace("(", "\\(").replace(
                                        ")", "\\)"
                                    )
                                )
                                break

        with open("filter.txt", "w") as filter_file:
            for dialog_class in get_dialog_classes():
                filter_file.write(dialog_class[1:] + ".*" + "\n")

            for hooked_method in hooked_methods:
                filter_file.write(hooked_method + "\n")

        argv[0] = os.path.abspath("dcc.py")
        argv.insert(0, sys.executable)

        proc = subprocess.Popen(argv, stderr=subprocess.STDOUT)
        proc.communicate()
    except Exception as e:
        getLogger("dcc").error("Dcc failed", exc_info=True)
    finally:
        restore_filters(backup_filter)
