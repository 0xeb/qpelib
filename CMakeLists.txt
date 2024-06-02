cmake_minimum_required(VERSION 3.12)

project(QuickPEInfo)

add_executable(check_kbd_driver check_kbd_driver.cpp qpeutil.hpp)
add_executable(main main.cpp qpeutil.hpp)